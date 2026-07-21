package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"
)

func Must(err error) {
	if err != nil {
		panic("panic: precondition violated: " + err.Error())
	}
}

func ValidateSurveyRaw(raw []byte) error {
	if len(raw) == 0 {
		return ErrEmptyContent
	}

	return nil
}

func ValidateDigest(digest []byte) error {
	if len(digest) != sha256.Size {
		return ErrInvalidDigest
	}

	return nil
}

func ValidateAttestationID(id string) error {
	if len(id) == 0 {
		return ErrEmptyAttestationID
	}

	return nil
}

func ValidateSignature(sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}

	return nil
}

func ValidateStampTime(stamped time.Time) error {
	if stamped.IsZero() {
		return ErrZeroStampTime
	}

	return nil
}

func ValidateAttestation(id AttestationID, stamped time.Time, sig Signature) error {
	if err := ValidateAttestationID(string(id)); err != nil {
		return err
	}

	if err := ValidateStampTime(stamped); err != nil {
		return err
	}

	return ValidateSignature(sig)
}
