package domain

import "time"

const digestSize = 32

type (
	AttestationID string
	SurveyContent struct{ raw []byte }
	Signature     []byte
	ContentHash   struct{ digest [digestSize]byte }
	Attestation   struct {
		Signature Signature
		Stamped   time.Time
		ID        AttestationID
		Hash      ContentHash
	}
)
