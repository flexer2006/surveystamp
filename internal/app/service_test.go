package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/flexer2006/surveystamp/internal/app"
	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/testutil"
)

func TestService_Issue(t *testing.T) {
	const id domain.AttestationID = "att-1"

	raw := []byte(`{"q":1}`)
	sig := bytes.Repeat([]byte{0x11}, ed25519.SignatureSize)
	boom := errors.New("boom")

	tests := []struct {
		name    string
		ctx     context.Context
		raw     []byte
		idErr   error
		signErr error
		saveErr error
		wantErr error
	}{
		{name: "ok", ctx: context.Background(), raw: raw},
		{name: "empty", ctx: context.Background(), wantErr: domain.ErrEmptyContent},
		{name: "canceled", ctx: testutil.HelperCanceled(), raw: raw, wantErr: context.Canceled},
		{name: "id_err", ctx: context.Background(), raw: raw, idErr: boom, wantErr: boom},
		{name: "sign_err", ctx: context.Background(), raw: raw, signErr: boom, wantErr: boom},
		{name: "save_err", ctx: context.Background(), raw: raw, saveErr: boom, wantErr: boom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepo{m: map[domain.AttestationID]domain.Attestation{}, err: tt.saveErr}
			svc := app.NewService(
				fakeClock{testutil.HelperStamp()},
				fakeID{id, tt.idErr},
				&fakeSigner{sig: sig, err: tt.signErr},
				repo,
			)

			got, err := svc.Issue(tt.ctx, tt.raw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				return
			}

			wantHash := domain.NewSurveyContent(raw).Hash()
			if got.ID != id || !got.Hash.Equal(wantHash) ||
				!got.Stamped.Equal(testutil.HelperStamp()) || string(got.Signature) != string(sig) {
				t.Fatalf("got %+v", got)
			}

			if _, ok := repo.m[id]; !ok {
				t.Fatal("not saved")
			}
		})
	}
}

func TestService_Verify(t *testing.T) {
	id := domain.AttestationID("att-1")
	att := domain.NewAttestation(
		id,
		domain.NewSurveyContent([]byte(id)).Hash(),
		testutil.HelperStamp(),
		bytes.Repeat([]byte{0x22}, ed25519.SignatureSize),
	)

	tests := []struct {
		name    string
		ctx     context.Context
		verify  error
		wantErr error
	}{
		{name: "ok", ctx: context.Background()},
		{name: "canceled", ctx: testutil.HelperCanceled(), wantErr: context.Canceled},
		{name: "bad_sig", ctx: context.Background(), verify: domain.ErrInvalidSignature, wantErr: domain.ErrInvalidSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepo{m: map[domain.AttestationID]domain.Attestation{att.ID: att}}
			err := app.NewService(
				fakeClock{testutil.HelperStamp()},
				fakeID{id: att.ID},
				&fakeSigner{verify: tt.verify},
				repo,
			).Verify(tt.ctx, att.ID)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

type fakeID struct {
	id  domain.AttestationID
	err error
}

func (f fakeID) NewID() (domain.AttestationID, error) { return f.id, f.err }

type fakeSigner struct {
	sig    domain.Signature
	err    error
	verify error
}

func (f *fakeSigner) Sign([]byte) (domain.Signature, error) { return f.sig, f.err }
func (f *fakeSigner) Verify([]byte, domain.Signature) error  { return f.verify }

type fakeRepo struct {
	m   map[domain.AttestationID]domain.Attestation
	err error
}

func (r *fakeRepo) Save(ctx context.Context, a domain.Attestation) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if r.err != nil {
		return r.err
	}

	r.m[a.ID] = a

	return nil
}

func (r *fakeRepo) GetByID(ctx context.Context, id domain.AttestationID) (domain.Attestation, error) {
	if err := ctx.Err(); err != nil {
		return domain.Attestation{}, err
	}

	return r.m[id], nil
}
