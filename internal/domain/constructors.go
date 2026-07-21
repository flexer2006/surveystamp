package domain

import (
	"slices"
	"time"
)

func NewAttestationID(id string) AttestationID {
	Must(ValidateAttestationID(id))

	return AttestationID(id)
}

func NewSignature(sig []byte) Signature {
	Must(ValidateSignature(sig))

	return slices.Clone(sig)
}

func NewAttestation(id AttestationID, hash ContentHash, stamped time.Time, sig Signature) Attestation {
	Must(ValidateAttestation(id, stamped, sig))

	return Attestation{ID: id, Hash: hash, Stamped: stamped, Signature: slices.Clone(sig)}
}

func NewSurveyContent(raw []byte) SurveyContent {
	Must(ValidateSurveyRaw(raw))

	return SurveyContent{raw: slices.Clone(raw)}
}

func NewContentHash(digest []byte) ContentHash {
	Must(ValidateDigest(digest))

	var hash ContentHash

	copy(hash.digest[:], digest)

	return hash
}
