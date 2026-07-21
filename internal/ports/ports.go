package ports

import (
	"context"
	"time"

	"github.com/flexer2006/surveystamp/internal/domain"
)

type (
	Clock interface {
		Now() time.Time
	}
	IDGenerator interface {
		NewID() (domain.AttestationID, error)
	}
	Signer interface {
		Sign(msg []byte) (domain.Signature, error)
		Verify(msg []byte, sig domain.Signature) error
	}
	AttestationRepository interface {
		Save(ctx context.Context, attestation domain.Attestation) error
		GetByID(ctx context.Context, id domain.AttestationID) (domain.Attestation, error)
	}
)
