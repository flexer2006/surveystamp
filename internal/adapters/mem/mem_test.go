package mem_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"
	"testing"

	"github.com/flexer2006/surveystamp/internal/adapters/mem"
	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/testutil"
)

func TestRepository_RoundTrip(t *testing.T) {
	repo := mem.New()
	id := domain.AttestationID("att-1")
	att := domain.NewAttestation(
		id,
		domain.NewSurveyContent([]byte(id)).Hash(),
		testutil.HelperStamp(),
		bytes.Repeat([]byte{0x11}, ed25519.SignatureSize),
	)

	if err := repo.Save(context.Background(), att); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GetByID(context.Background(), att.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != att.ID || !got.Hash.Equal(att.Hash) || string(got.Signature) != string(att.Signature) {
		t.Fatalf("got %+v", got)
	}
}

func TestRepository_Errors(t *testing.T) {
	id := domain.AttestationID("att-1")
	att := domain.NewAttestation(
		id,
		domain.NewSurveyContent([]byte(id)).Hash(),
		testutil.HelperStamp(),
		bytes.Repeat([]byte{0x11}, ed25519.SignatureSize),
	)

	tests := []struct {
		name string
		run  func(*mem.Repository) error
		want error
	}{
		{
			name: "missing",
			run: func(r *mem.Repository) error {
				_, err := r.GetByID(context.Background(), "nope")

				return err
			},
			want: domain.ErrNotFound,
		},
		{
			name: "save_canceled",
			run:  func(r *mem.Repository) error { return r.Save(testutil.HelperCanceled(), att) },
			want: context.Canceled,
		},
		{
			name: "get_canceled",
			run: func(r *mem.Repository) error {
				_ = r.Save(context.Background(), att)
				_, err := r.GetByID(testutil.HelperCanceled(), att.ID)

				return err
			},
			want: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(mem.New()); !errors.Is(err, tt.want) {
				t.Fatalf("err=%v want %v", err, tt.want)
			}
		})
	}
}

func TestRepository_Clone(t *testing.T) {
	repo := mem.New()
	id := domain.AttestationID("att-1")
	att := domain.NewAttestation(
		id,
		domain.NewSurveyContent([]byte(id)).Hash(),
		testutil.HelperStamp(),
		bytes.Repeat([]byte{0x22}, ed25519.SignatureSize),
	)
	_ = repo.Save(context.Background(), att)

	att.Signature[0] ^= 0xff

	got, _ := repo.GetByID(context.Background(), att.ID)
	if got.Signature[0] == att.Signature[0] {
		t.Fatal("aliased with caller")
	}

	got.Signature[0] ^= 0xff

	got2, _ := repo.GetByID(context.Background(), att.ID)
	if got2.Signature[0] == got.Signature[0] {
		t.Fatal("aliased with store")
	}
}

func TestRepository_Concurrent(t *testing.T) {
	repo := mem.New()

	for i := range 64 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			id := domain.AttestationID("att-" + strconv.Itoa(i))
			a := domain.NewAttestation(
				id,
				domain.NewSurveyContent([]byte(id)).Hash(),
				testutil.HelperStamp(),
				bytes.Repeat([]byte{byte(i)}, ed25519.SignatureSize),
			)

			if err := repo.Save(context.Background(), a); err != nil {
				t.Fatal(err)
			}

			got, err := repo.GetByID(context.Background(), a.ID)
			if err != nil || got.ID != a.ID {
				t.Fatalf("err=%v id=%q", err, got.ID)
			}
		})
	}
}
