package domain_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"
	"testing/quick"
	"time"

	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/testutil"
)

func TestValidate(t *testing.T) {
	sig := bytes.Repeat([]byte{0}, ed25519.SignatureSize)
	stamp := testutil.HelperStamp()

	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"raw_nil", func() error { return domain.ValidateSurveyRaw(nil) }, domain.ErrEmptyContent},
		{"raw_empty", func() error { return domain.ValidateSurveyRaw([]byte{}) }, domain.ErrEmptyContent},
		{"raw_ok", func() error { return domain.ValidateSurveyRaw([]byte(`{}`)) }, nil},
		{"digest_bad", func() error { return domain.ValidateDigest(nil) }, domain.ErrInvalidDigest},
		{"digest_ok", func() error { return domain.ValidateDigest(make([]byte, sha256.Size)) }, nil},
		{"id_empty", func() error { return domain.ValidateAttestationID("") }, domain.ErrEmptyAttestationID},
		{"id_ok", func() error { return domain.ValidateAttestationID("a") }, nil},
		{"sig_bad", func() error { return domain.ValidateSignature(nil) }, domain.ErrInvalidSignature},
		{"sig_ok", func() error { return domain.ValidateSignature(sig) }, nil},
		{"time_zero", func() error { return domain.ValidateStampTime(time.Time{}) }, domain.ErrZeroStampTime},
		{"time_ok", func() error { return domain.ValidateStampTime(stamp) }, nil},
		{"att_bad_id", func() error { return domain.ValidateAttestation("", stamp, sig) }, domain.ErrEmptyAttestationID},
		{"att_ok", func() error { return domain.ValidateAttestation("a", stamp, sig) }, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, tt.want) {
				t.Fatalf("err=%v want %v", err, tt.want)
			}
		})
	}
}

func TestNewSurveyContent(t *testing.T) {
	raw := []byte("hello")

	mustPanic(t, func() { _ = domain.NewSurveyContent(nil) })

	c := domain.NewSurveyContent(raw)
	if !bytes.Equal(c.Canonical(), raw) {
		t.Fatal("canonical mismatch")
	}

	raw[0] ^= 0xff
	if bytes.Equal(c.Canonical(), raw) {
		t.Fatal("input not cloned")
	}

	cp := c.Canonical()

	cp[0] = 'Z'
	if bytes.Equal(c.Canonical(), cp) {
		t.Fatal("canonical not copied")
	}

	sum := sha256.Sum256([]byte("hello"))
	if !c.Hash().Equal(domain.NewContentHash(sum[:])) {
		t.Fatal("hash mismatch")
	}
}

func TestNewContentHash(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, sha256.Size)

	mustPanic(t, func() { _ = domain.NewContentHash(nil) })

	h := domain.NewContentHash(digest)
	if !bytes.Equal(h.Bytes(), digest) {
		t.Fatal("bytes mismatch")
	}

	digest[0] ^= 0xff
	if bytes.Equal(h.Bytes(), digest) {
		t.Fatal("digest not copied")
	}

	b := h.Bytes()
	b[0] ^= 0xff

	if !h.Equal(domain.NewContentHash(bytes.Repeat([]byte{0xab}, sha256.Size))) {
		t.Fatal("Bytes mutates hash")
	}

	if h.Equal(domain.NewContentHash(bytes.Repeat([]byte{0xcd}, sha256.Size))) {
		t.Fatal("equal true for different digests")
	}
}

func TestNewAttestationID(t *testing.T) {
	mustPanic(t, func() { _ = domain.NewAttestationID("") })

	if got := domain.NewAttestationID("id"); got != "id" {
		t.Fatalf("got %q", got)
	}
}

func TestNewSignature(t *testing.T) {
	sig := bytes.Repeat([]byte{0x7f}, ed25519.SignatureSize)

	mustPanic(t, func() { _ = domain.NewSignature(nil) })

	got := domain.NewSignature(sig)
	if !bytes.Equal(got, sig) {
		t.Fatal("mismatch")
	}

	sig[0] ^= 0xff
	if bytes.Equal(got, sig) {
		t.Fatal("not cloned")
	}
}

func TestNewAttestation(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 42)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	hash := domain.NewSurveyContent([]byte(`{"t":1}`)).Hash()
	msg := hash.Bytes()
	sig := ed25519.Sign(priv, msg)
	id := domain.AttestationID("att-1")
	stamp := testutil.HelperStamp()

	got := domain.NewAttestation(id, hash, stamp, sig)
	if got.ID != id || !got.Hash.Equal(hash) || !got.Stamped.Equal(stamp) || !bytes.Equal(got.Signature, sig) {
		t.Fatalf("got %+v", got)
	}

	if !ed25519.Verify(pub, msg, got.Signature) {
		t.Fatal("verify failed")
	}

	sig[0] ^= 0xff
	if bytes.Equal(got.Signature, sig) {
		t.Fatal("sig not cloned")
	}

	for _, tt := range []struct {
		name string
		id   domain.AttestationID
		ts   time.Time
		sig  domain.Signature
	}{
		{"empty_id", "", stamp, bytes.Repeat([]byte{0}, ed25519.SignatureSize)},
		{"zero_time", id, time.Time{}, bytes.Repeat([]byte{0}, ed25519.SignatureSize)},
		{"bad_sig", id, stamp, []byte("x")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mustPanic(t, func() { _ = domain.NewAttestation(tt.id, hash, tt.ts, tt.sig) })
		})
	}
}

func TestQuick_HashStable(t *testing.T) {
	err := quick.Check(func(raw []byte) bool {
		if len(raw) == 0 {
			return true
		}

		h1 := domain.NewSurveyContent(raw).Hash()
		h2 := domain.NewSurveyContent(slices.Clone(raw)).Hash()
		sum := sha256.Sum256(raw)

		return h1.Equal(h2) && bytes.Equal(h1.Bytes(), sum[:])
	}, &quick.Config{MaxCount: 128})
	if err != nil {
		t.Fatal(err)
	}
}

func TestQuick_EqualSymmetric(t *testing.T) {
	err := quick.Check(func(a, b byte) bool {
		ha := domain.NewContentHash(bytes.Repeat([]byte{a}, sha256.Size))
		hb := domain.NewContentHash(bytes.Repeat([]byte{b}, sha256.Size))

		return ha.Equal(hb) == hb.Equal(ha) && ha.Equal(ha)
	}, &quick.Config{MaxCount: 64})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMust_PanicMessage(t *testing.T) {
	defer func() {
		msg, ok := recover().(string)
		if !ok || !strings.Contains(msg, "panic: precondition violated:") {
			t.Fatalf("unexpected panic %#v", msg)
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
