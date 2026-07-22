package crypt_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"testing/cryptotest"

	"github.com/flexer2006/surveystamp/internal/adapters/crypt"
	"github.com/flexer2006/surveystamp/internal/domain"
)

func TestSigner_RoundTrip(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 7)

	s, err := crypt.Generate(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("msg")

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Verify(msg, sig); err != nil {
		t.Fatal(err)
	}
}

func TestSigner_Errors(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 11)

	s, err := crypt.Generate(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("ok")

	good, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	bad := bytes.Clone(good)
	bad[0] ^= 0xff

	tests := []struct {
		name string
		run  func() error
		want error
	}{
		{"tampered", func() error { return s.Verify(msg, bad) }, domain.ErrInvalidSignature},
		{"short_sig", func() error { return s.Verify(msg, []byte("x")) }, domain.ErrInvalidSignature},
		{"bad_key", func() error {
			_, err := crypt.New(nil)

			return err
		}, crypt.ErrInvalidKey},
		{"generate_err", func() error {
			_, err := crypt.Generate(errReader{})

			return err
		}, io.ErrUnexpectedEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, tt.want) {
				t.Fatalf("err=%v want %v", err, tt.want)
			}
		})
	}
}

func TestSigner_Clone(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 13)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	s, err := crypt.New(priv)
	if err != nil {
		t.Fatal(err)
	}

	priv[0] ^= 0xff

	msg := []byte("clone")

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	kept := bytes.Clone(sig)
	sig[0] ^= 0xff

	if err := s.Verify(msg, kept); err != nil {
		t.Fatal("Sign aliased")
	}
}

func TestNew_NormalizesCorruptPublicHalf(t *testing.T) {
	seed := bytes.Repeat([]byte{0x7e}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	priv[ed25519.SeedSize] ^= 0xff

	s, err := crypt.New(priv)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("x")

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Verify(msg, sig); err != nil {
		t.Fatal(err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
