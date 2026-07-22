package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/flexer2006/surveystamp/internal/domain"
)

type Service interface {
	Issue(ctx context.Context, raw []byte) (*domain.Attestation, error)
	Verify(ctx context.Context, id domain.AttestationID) error
}

type handler struct {
	svc Service
}

type attestationResponse struct {
	ID        string `json:"id"`
	Hash      string `json:"hash"`
	Stamped   string `json:"stamped"`
	Signature string `json:"signature"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func New(svc Service) http.Handler {
	h := new(handler{svc: svc})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /attestations", h.issue)
	mux.HandleFunc("POST /attestations/{id}/verify", h.verify)

	return mux
}

func (h *handler) issue(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, err)

		return
	}

	att, err := h.svc.Issue(r.Context(), raw)
	if err != nil {
		writeError(w, err)

		return
	}

	writeJSON(w, http.StatusCreated, attestationResponse{
		ID:        string(att.ID),
		Hash:      hex.EncodeToString(att.Hash.Bytes()),
		Stamped:   att.Stamped.UTC().Format(time.RFC3339Nano),
		Signature: base64.StdEncoding.EncodeToString(att.Signature),
	})
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	err := h.svc.Verify(r.Context(), domain.AttestationID(r.PathValue("id")))
	if err != nil {
		writeError(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, statusOf(err), errorResponse{Error: err.Error()})
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, domain.ErrEmptyContent):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrInvalidSignature):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
