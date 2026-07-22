package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flexer2006/surveystamp/internal/adapters/api"
	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/testutil"
)

func TestHandler_RoundTrip(t *testing.T) {
	raw := []byte(`{"q":1}`)
	att := sampleAttestation()
	svc := &fakeService{att: att}
	h := api.New(svc)

	rec := do(t, h, http.MethodPost, "/attestations", raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue code=%d body=%s", rec.Code, rec.Body.Bytes())
	}

	if !bytes.Equal(svc.raw, raw) {
		t.Fatalf("raw=%q", svc.raw)
	}

	var got struct {
		ID        string `json:"id"`
		Hash      string `json:"hash"`
		Stamped   string `json:"stamped"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}

	wantHash := hex.EncodeToString(att.Hash.Bytes())
	wantSig := base64.StdEncoding.EncodeToString(att.Signature)

	if got.ID != string(att.ID) || got.Hash != wantHash ||
		got.Stamped != att.Stamped.UTC().Format(time.RFC3339Nano) || got.Signature != wantSig {
		t.Fatalf("got %+v", got)
	}

	rec = do(t, h, http.MethodPost, "/attestations/"+string(att.ID)+"/verify", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify code=%d", rec.Code)
	}

	if svc.verifyID != att.ID {
		t.Fatalf("verify id=%q", svc.verifyID)
	}
}

func TestHandler_Errors(t *testing.T) {
	att := sampleAttestation()

	tests := []struct {
		name   string
		svc    *fakeService
		method string
		path   string
		body   []byte
		code   int
	}{
		{
			name:   "issue_empty",
			svc:    &fakeService{issueErr: domain.ErrEmptyContent},
			method: http.MethodPost,
			path:   "/attestations",
			code:   http.StatusBadRequest,
		},
		{
			name:   "verify_missing",
			svc:    &fakeService{verifyErr: domain.ErrNotFound},
			method: http.MethodPost,
			path:   "/attestations/nope/verify",
			code:   http.StatusNotFound,
		},
		{
			name:   "verify_bad_sig",
			svc:    &fakeService{verifyErr: domain.ErrInvalidSignature},
			method: http.MethodPost,
			path:   "/attestations/" + string(att.ID) + "/verify",
			code:   http.StatusUnprocessableEntity,
		},
		{
			name:   "issue_internal",
			svc:    &fakeService{issueErr: io.ErrUnexpectedEOF},
			method: http.MethodPost,
			path:   "/attestations",
			body:   []byte(`{}`),
			code:   http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, api.New(tt.svc), tt.method, tt.path, tt.body)
			if rec.Code != tt.code {
				t.Fatalf("code=%d want %d body=%s", rec.Code, tt.code, rec.Body.Bytes())
			}
		})
	}
}

func TestHandler_IssueBodyErr(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/attestations", errReader{})
	rec := httptest.NewRecorder()
	api.New(&fakeService{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d", rec.Code)
	}
}

func sampleAttestation() domain.Attestation {
	id := domain.AttestationID("att-1")

	return domain.NewAttestation(
		id,
		domain.NewSurveyContent([]byte(id)).Hash(),
		testutil.HelperStamp(),
		bytes.Repeat([]byte{0x11}, ed25519.SignatureSize),
	)
}

func do(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}

	req := httptest.NewRequest(method, path, r)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

type fakeService struct {
	att       domain.Attestation
	raw       []byte
	verifyID  domain.AttestationID
	issueErr  error
	verifyErr error
}

func (f *fakeService) Issue(_ context.Context, raw []byte) (*domain.Attestation, error) {
	f.raw = bytes.Clone(raw)
	if f.issueErr != nil {
		return nil, f.issueErr
	}

	return new(f.att), nil
}

func (f *fakeService) Verify(_ context.Context, id domain.AttestationID) error {
	f.verifyID = id

	return f.verifyErr
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
