package domain

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
)

func TestValidateSurveyRaw(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		wantErr error
	}{
		{name: "nil", raw: nil, wantErr: ErrEmptyContent},
		{name: "empty", raw: []byte{}, wantErr: ErrEmptyContent},
		{name: "ok", raw: []byte(`{"q":1}`), wantErr: nil},
		{name: "binary", raw: []byte{0x00, 0xff}, wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSurveyRaw(tt.raw)
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
		{name: "nil", digest: nil, wantErr: ErrInvalidDigest},
		{name: "too_short", digest: make([]byte, sha256.Size-1), wantErr: ErrInvalidDigest},
		{name: "too_long", digest: make([]byte, sha256.Size+1), wantErr: ErrInvalidDigest},
		{name: "exact", digest: make([]byte, sha256.Size), wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDigest(tt.digest)
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
		{name: "empty", id: "", wantErr: ErrEmptyAttestationID},
		{name: "ok", id: "att-1", wantErr: nil},
		{name: "space", id: " ", wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestationID(tt.id)
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
		{name: "nil", sig: nil, wantErr: ErrInvalidSignature},
		{name: "empty", sig: []byte{}, wantErr: ErrInvalidSignature},
		{name: "short", sig: make([]byte, ed25519.SignatureSize-1), wantErr: ErrInvalidSignature},
		{name: "long", sig: make([]byte, ed25519.SignatureSize+1), wantErr: ErrInvalidSignature},
		{name: "exact", sig: make([]byte, ed25519.SignatureSize), wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignature(tt.sig)
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
		{name: "zero", stamped: time.Time{}, wantErr: ErrZeroStampTime},
		{name: "unix_epoch", stamped: time.Unix(0, 0).UTC(), wantErr: nil},
		{name: "now", stamped: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStampTime(tt.stamped)
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
		id      AttestationID
		stamped time.Time
		sig     Signature
		wantErr error
	}{
		{name: "empty_id", id: "", stamped: validTime, sig: validSig, wantErr: ErrEmptyAttestationID},
		{name: "zero_time", id: "att-1", stamped: time.Time{}, sig: validSig, wantErr: ErrZeroStampTime},
		{name: "bad_sig", id: "att-1", stamped: validTime, sig: Signature([]byte("nope")), wantErr: ErrInvalidSignature},
		{name: "ok", id: "att-1", stamped: validTime, sig: validSig, wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestation(tt.id, tt.stamped, tt.sig)
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
				mustPanic(t, func() { _ = NewSurveyContent(tt.raw) })
				return
			}
			c := NewSurveyContent(tt.raw)
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
	c := NewSurveyContent([]byte("abc"))
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
			c := NewSurveyContent(tt.raw)
			want := sha256.Sum256(tt.raw)
			got := c.Hash().Bytes()
			if !bytes.Equal(got, want[:]) {
				t.Fatalf("Hash()=%x want %x", got, want)
			}
			if !c.Hash().Equal(NewContentHash(want[:])) {
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
				mustPanic(t, func() { _ = NewContentHash(tt.digest) })
				return
			}
			h := NewContentHash(tt.digest)
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
	a := NewContentHash(aDigest)
	b := NewContentHash(bDigest)
	a2 := NewContentHash(aDigest)
	tests := []struct {
		name  string
		left  ContentHash
		right ContentHash
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
		want      AttestationID
	}{
		{name: "empty_panics", id: "", wantPanic: true},
		{name: "ok", id: "id-42", wantPanic: false, want: AttestationID("id-42")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				mustPanic(t, func() { _ = NewAttestationID(tt.id) })
				return
			}
			if got := NewAttestationID(tt.id); got != tt.want {
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
				mustPanic(t, func() { _ = NewSignature(tt.sig) })
				return
			}
			got := NewSignature(tt.sig)
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

func TestNewAttestation(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := NewSurveyContent([]byte(`{"title":"t"}`)).Hash()
	msg := hash.Bytes()
	sig := ed25519.Sign(priv, msg)
	stamped := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	id := AttestationID("att-100")
	tests := []struct {
		name      string
		id        AttestationID
		hash      ContentHash
		stamped   time.Time
		sig       Signature
		wantPanic bool
	}{
		{name: "ok", id: id, hash: hash, stamped: stamped, sig: sig, wantPanic: false},
		{name: "empty_id_panics", id: "", hash: hash, stamped: stamped, sig: sig, wantPanic: true},
		{name: "zero_time_panics", id: id, hash: hash, stamped: time.Time{}, sig: sig, wantPanic: true},
		{name: "bad_sig_panics", id: id, hash: hash, stamped: stamped, sig: Signature([]byte("x")), wantPanic: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				mustPanic(t, func() {
					_ = NewAttestation(tt.id, tt.hash, tt.stamped, tt.sig)
				})
				return
			}
			got := NewAttestation(tt.id, tt.hash, tt.stamped, tt.sig)
			if got.ID != tt.id {
				t.Fatalf("ID=%q want %q", got.ID, tt.id)
			}
			if !got.Hash.Equal(tt.hash) {
				t.Fatal("hash mismatch")
			}
			if !got.Stamped.Equal(tt.stamped) {
				t.Fatalf("Stamped=%v want %v", got.Stamped, tt.stamped)
			}
			if !bytes.Equal(got.Signature, tt.sig) {
				t.Fatal("signature mismatch")
			}
			if !ed25519.Verify(pub, msg, got.Signature) {
				t.Fatal("ed25519.Verify failed")
			}
			tt.sig[0] ^= 0xff
			if bytes.Equal(got.Signature, tt.sig) {
				t.Fatal("signature was not cloned")
			}
		})
	}
}

func TestQuick_SurveyContentHashStableAndInjectiveEnough(t *testing.T) {
	err := quick.Check(func(raw []byte) bool {
		if len(raw) == 0 {
			return true
		}
		h1 := NewSurveyContent(raw).Hash()
		h2 := NewSurveyContent(append([]byte(nil), raw...)).Hash()
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
		a := NewContentHash(da)
		b := NewContentHash(db)
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
	Must(ErrEmptyContent)
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
