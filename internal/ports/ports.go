package ports

import (
	"context"
	"time"

	"github.com/flexer2006/surveystamp/internal/domain"
)

type (
	Clock       interface{ Now() time.Time }
	IDGenerator interface {
		NewID() (domain.AttestationID, error)
	}
	Signer interface {
		Sign([]byte) (domain.Signature, error)
		Verify([]byte, domain.Signature) error
	}
	AttestationRepository interface {
		Save(context.Context, domain.Attestation) error
		GetByID(context.Context, domain.AttestationID) (domain.Attestation, error)
	}
)
