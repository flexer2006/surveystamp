package domain_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"testing/cryptotest"
	"testing/quick"
	"time"

	"github.com/flexer2006/surveystamp/internal/domain"
)

func TestValidateSurveyRaw(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		wantErr error
	}{
		{name: "nil", raw: nil, wantErr: domain.ErrEmptyContent},
		{name: "empty", raw: []byte{}, wantErr: domain.ErrEmptyContent},
		{name: "ok", raw: []byte(`{"q":1}`), wantErr: nil},
		{name: "binary", raw: []byte{0x00, 0xff}, wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateSurveyRaw(tt.raw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDigest(t *testing.T) {
	tests := []struct {
		name    string
		digest  []byte
		wantErr error
	}{
		{name: "nil", digest: nil, wantErr: domain.ErrInvalidDigest},
		{name: "too_short", digest: make([]byte, sha256.Size-1), wantErr: domain.ErrInvalidDigest},
		{name: "too_long", digest: make([]byte, sha256.Size+1), wantErr: domain.ErrInvalidDigest},
		{name: "exact", digest: make([]byte, sha256.Size), wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateDigest(tt.digest)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAttestationID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{name: "empty", id: "", wantErr: domain.ErrEmptyAttestationID},
		{name: "ok", id: "att-1", wantErr: nil},
		{name: "space", id: " ", wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateAttestationID(tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSignature(t *testing.T) {
	tests := []struct {
		name    string
		sig     []byte
		wantErr error
	}{
		{name: "nil", sig: nil, wantErr: domain.ErrInvalidSignature},
		{name: "empty", sig: []byte{}, wantErr: domain.ErrInvalidSignature},
		{name: "short", sig: make([]byte, ed25519.SignatureSize-1), wantErr: domain.ErrInvalidSignature},
		{name: "long", sig: make([]byte, ed25519.SignatureSize+1), wantErr: domain.ErrInvalidSignature},
		{name: "exact", sig: make([]byte, ed25519.SignatureSize), wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateSignature(tt.sig)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateStampTime(t *testing.T) {
	tests := []struct {
		name    string
		stamped time.Time
		wantErr error
	}{
		{name: "zero", stamped: time.Time{}, wantErr: domain.ErrZeroStampTime},
		{name: "unix_epoch", stamped: time.Unix(0, 0).UTC(), wantErr: nil},
		{name: "now", stamped: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateStampTime(tt.stamped)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAttestation(t *testing.T) {
	validSig := make([]byte, ed25519.SignatureSize)
	validTime := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		id      domain.AttestationID
		stamped time.Time
		sig     domain.Signature
		wantErr error
	}{
		{name: "empty_id", id: "", stamped: validTime, sig: validSig, wantErr: domain.ErrEmptyAttestationID},
		{name: "zero_time", id: "att-1", stamped: time.Time{}, sig: validSig, wantErr: domain.ErrZeroStampTime},
		{name: "bad_sig", id: "att-1", stamped: validTime, sig: []byte("nope"), wantErr: domain.ErrInvalidSignature},
		{name: "ok", id: "att-1", stamped: validTime, sig: validSig, wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := domain.ValidateAttestation(tt.id, tt.stamped, tt.sig)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewSurveyContent(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		wantPanic bool
	}{
		{name: "nil_panics", raw: nil, wantPanic: true},
		{name: "empty_panics", raw: []byte{}, wantPanic: true},
		{name: "ok", raw: []byte("hello"), wantPanic: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				mustPanic(t, func() { _ = domain.NewSurveyContent(tt.raw) })

				return
			}

			c := domain.NewSurveyContent(tt.raw)
			if !bytes.Equal(c.Canonical(), tt.raw) {
				t.Fatalf("Canonical()=%q want %q", c.Canonical(), tt.raw)
			}

			tt.raw[0] ^= 0xff
			if bytes.Equal(c.Canonical(), tt.raw) {
				t.Fatal("input was not cloned")
			}
		})
	}
}

func TestSurveyContent_CanonicalIsDefensiveCopy(t *testing.T) {
	c := domain.NewSurveyContent([]byte("abc"))
	got := c.Canonical()
	got[0] = 'Z'

	if bytes.Equal(c.Canonical(), got) {
		t.Fatal("Canonical() is not a copy")
	}
}

func TestSurveyContent_Hash(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "text", raw: []byte("survey")},
		{name: "json", raw: []byte(`{"a":1}`)},
		{name: "binary", raw: []byte{0, 1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := domain.NewSurveyContent(tt.raw)
			want := sha256.Sum256(tt.raw)
			got := c.Hash().Bytes()

			if !bytes.Equal(got, want[:]) {
				t.Fatalf("Hash()=%x want %x", got, want)
			}

			if !c.Hash().Equal(domain.NewContentHash(want[:])) {
				t.Fatal("Hash/Equal mismatch")
			}
		})
	}
}

func TestNewContentHash(t *testing.T) {
	valid := make([]byte, sha256.Size)
	valid[0] = 0xab

	tests := []struct {
		name      string
		digest    []byte
		wantPanic bool
	}{
		{name: "nil_panics", digest: nil, wantPanic: true},
		{name: "short_panics", digest: make([]byte, 16), wantPanic: true},
		{name: "long_panics", digest: make([]byte, 33), wantPanic: true},
		{name: "ok", digest: valid, wantPanic: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				mustPanic(t, func() { _ = domain.NewContentHash(tt.digest) })

				return
			}

			h := domain.NewContentHash(tt.digest)
			if !bytes.Equal(h.Bytes(), tt.digest) {
				t.Fatalf("Bytes()=%x want %x", h.Bytes(), tt.digest)
			}

			tt.digest[0] ^= 0xff
			if bytes.Equal(h.Bytes(), tt.digest) {
				t.Fatal("digest was not copied")
			}
		})
	}
}

func TestContentHash_BytesAndEqual(t *testing.T) {
	aDigest := bytes.Repeat([]byte{0x11}, sha256.Size)
	bDigest := bytes.Repeat([]byte{0x22}, sha256.Size)
	a := domain.NewContentHash(aDigest)
	b := domain.NewContentHash(bDigest)
	a2 := domain.NewContentHash(aDigest)

	tests := []struct {
		name  string
		left  domain.ContentHash
		right domain.ContentHash
		want  bool
	}{
		{name: "same", left: a, right: a2, want: true},
		{name: "different", left: a, right: b, want: false},
		{name: "reflexive", left: a, right: a, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.left.Equal(tt.right); got != tt.want {
				t.Fatalf("Equal()=%v want %v", got, tt.want)
			}
		})
	}

	cloned := a.Bytes()
	cloned[0] ^= 0xff

	if !a.Equal(a2) {
		t.Fatal("Bytes() copy mutated hash")
	}
}

func TestNewAttestationID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		wantPanic bool
		want      domain.AttestationID
	}{
		{name: "empty_panics", id: "", wantPanic: true},
		{name: "ok", id: "id-42", wantPanic: false, want: "id-42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				mustPanic(t, func() { _ = domain.NewAttestationID(tt.id) })

				return
			}

			if got := domain.NewAttestationID(tt.id); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestNewSignature(t *testing.T) {
	valid := make([]byte, ed25519.SignatureSize)
	valid[3] = 0x7f

	tests := []struct {
		name      string
		sig       []byte
		wantPanic bool
	}{
		{name: "nil_panics", sig: nil, wantPanic: true},
		{name: "short_panics", sig: make([]byte, 8), wantPanic: true},
		{name: "ok", sig: valid, wantPanic: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				mustPanic(t, func() { _ = domain.NewSignature(tt.sig) })

				return
			}

			got := domain.NewSignature(tt.sig)
			if !bytes.Equal(got, tt.sig) {
				t.Fatalf("got %x want %x", got, tt.sig)
			}

			tt.sig[0] ^= 0xff
			if bytes.Equal(got, tt.sig) {
				t.Fatal("signature was not cloned")
			}
		})
	}
}

func TestNewAttestation_OK(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)

	pub, privy, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	hash := domain.NewSurveyContent([]byte(`{"title":"t"}`)).Hash()
	msg := hash.Bytes()
	sig := ed25519.Sign(privy, msg)
	stamped := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	id := domain.AttestationID("att-100")

	got := domain.NewAttestation(id, hash, stamped, sig)
	if got.ID != id || !got.Hash.Equal(hash) || !got.Stamped.Equal(stamped) || !bytes.Equal(got.Signature, sig) {
		t.Fatalf("got %+v", got)
	}

	if !ed25519.Verify(pub, msg, got.Signature) {
		t.Fatal("ed25519.Verify failed")
	}

	sig[0] ^= 0xff
	if bytes.Equal(got.Signature, sig) {
		t.Fatal("signature was not cloned")
	}
}

func TestNewAttestation_Panics(t *testing.T) {
	hash := domain.NewSurveyContent([]byte(`{"title":"t"}`)).Hash()
	sig := make([]byte, ed25519.SignatureSize)
	stamped := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	id := domain.AttestationID("att-100")

	tests := []struct {
		name    string
		id      domain.AttestationID
		stamped time.Time
		sig     domain.Signature
	}{
		{name: "empty_id", id: "", stamped: stamped, sig: sig},
		{name: "zero_time", id: id, stamped: time.Time{}, sig: sig},
		{name: "bad_sig", id: id, stamped: stamped, sig: []byte("x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustPanic(t, func() {
				_ = domain.NewAttestation(tt.id, hash, tt.stamped, tt.sig)
			})
		})
	}
}

func TestQuick_SurveyContentHashStableAndInjectiveEnough(t *testing.T) {
	err := quick.Check(func(raw []byte) bool {
		if len(raw) == 0 {
			return true
		}

		h1 := domain.NewSurveyContent(raw).Hash()
		h2 := domain.NewSurveyContent(append([]byte(nil), raw...)).Hash()
		sum := sha256.Sum256(raw)

		return h1.Equal(h2) && bytes.Equal(h1.Bytes(), sum[:])
	}, &quick.Config{MaxCount: 200})
	if err != nil {
		t.Fatal(err)
	}
}

func TestQuick_ContentHashEqualSymmetric(t *testing.T) {
	err := quick.Check(func(aByte, bByte byte) bool {
		da := bytes.Repeat([]byte{aByte}, sha256.Size)
		db := bytes.Repeat([]byte{bByte}, sha256.Size)
		a := domain.NewContentHash(da)
		b := domain.NewContentHash(db)

		return a.Equal(b) == b.Equal(a) && a.Equal(a)
	}, &quick.Config{MaxCount: 64})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMust_PanicMessage(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}

		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic type %T", r)
		}

		if !strings.Contains(msg, "panic: precondition violated:") {
			t.Fatalf("unexpected panic %q", msg)
		}
	}()

	domain.Must(domain.ErrEmptyContent)
}

func mustPanic(t *testing.T, fn func()) {
	t.Helper()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()

	fn()
}
