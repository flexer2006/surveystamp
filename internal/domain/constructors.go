package domain

import (
	"slices"
	"time"
)

func NewAttestationID(id string) AttestationID {
	must(ValidateAttestationID(id))
	return AttestationID(id)
}

func NewSignature(sig []byte) Signature {
	must(ValidateSignature(sig))
	return Signature(slices.Clone(sig))
}

func NewAttestation(id AttestationID, hash ContentHash, stamped time.Time, sig Signature) Attestation {
	must(ValidateAttestation(id, stamped, sig))
	return Attestation{ID: id, Hash: hash, Stamped: stamped, Signature: Signature(slices.Clone(sig))}
}

func NewSurveyContent(raw []byte) SurveyContent {
	must(ValidateSurveyRaw(raw))
	return SurveyContent{raw: slices.Clone(raw)}
}

func NewContentHash(digest []byte) ContentHash {
	must(ValidateDigest(digest))
	var hash ContentHash
	copy(hash.digest[:], digest)
	return hash
}
