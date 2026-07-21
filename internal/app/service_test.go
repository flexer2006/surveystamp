package app_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/flexer2006/surveystamp/internal/app"
	"github.com/flexer2006/surveystamp/internal/domain"
)

func TestService_Issue(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	id := domain.AttestationID("att-1")
	sig := make([]byte, ed25519.SignatureSize)
	raw := []byte(`{"q":1}`)
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
		{name: "canceled", ctx: canceledCtx(), raw: raw, wantErr: context.Canceled},
		{name: "id_err", ctx: context.Background(), raw: raw, idErr: boom, wantErr: boom},
		{name: "sign_err", ctx: context.Background(), raw: raw, signErr: boom, wantErr: boom},
		{name: "save_err", ctx: context.Background(), raw: raw, saveErr: boom, wantErr: boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepo{m: map[domain.AttestationID]domain.Attestation{}, err: tt.saveErr}
			svc := app.NewService(fakeClock{now}, fakeID{id, tt.idErr}, &fakeSigner{sig: sig, err: tt.signErr}, repo)

			got, err := svc.Issue(tt.ctx, tt.raw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				return
			}

			h := domain.NewSurveyContent(raw).Hash()
			if got.ID != id || !got.Hash.Equal(h) || !got.Stamped.Equal(now) || string(got.Signature) != string(sig) {
				t.Fatalf("got %+v", got)
			}

			if _, ok := repo.m[id]; !ok {
				t.Fatal("not saved")
			}
		})
	}
}

func TestService_Verify(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	id := domain.AttestationID("att-1")
	sig := make([]byte, ed25519.SignatureSize)
	att := domain.NewAttestation(id, domain.NewSurveyContent([]byte(`{"q":1}`)).Hash(), now, sig)

	tests := []struct {
		name    string
		ctx     context.Context
		id      domain.AttestationID
		verify  error
		wantErr error
	}{
		{name: "ok", ctx: context.Background(), id: id},
		{name: "bad_sig", ctx: context.Background(),
			id: id, verify: domain.ErrInvalidSignature, wantErr: domain.ErrInvalidSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepo{m: map[domain.AttestationID]domain.Attestation{id: att}}

			err := app.NewService(fakeClock{now}, fakeID{id: id}, &fakeSigner{verify: tt.verify}, repo).Verify(tt.ctx, tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	return ctx
}

type fakeClock struct{ t time.Time }

func (f fakeClock) Now() time.Time { return f.t }

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
func (f *fakeSigner) Verify([]byte, domain.Signature) error { return f.verify }

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
