package domain

import "errors"

var (
	ErrZeroStampTime      = errors.New("stamp time is zero")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrEmptyAttestationID = errors.New("attestation id is empty")
	ErrEmptyContent       = errors.New("survey content is empty")
	ErrInvalidDigest      = errors.New("content hash digest must be 32 bytes")
	ErrNotFound           = errors.New("attestation not found")
)
