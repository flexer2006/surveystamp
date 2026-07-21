package app

import (
	"context"
	"time"

	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/ports"
)

type Service struct {
	clock  ports.Clock
	ids    ports.IDGenerator
	signer ports.Signer
	repo   ports.AttestationRepository
}

func NewService(
	clock ports.Clock,
	ids ports.IDGenerator,
	signer ports.Signer,
	repo ports.AttestationRepository,
) *Service {
	return new(Service{clock: clock, ids: ids, signer: signer, repo: repo})
}

func (s *Service) Issue(ctx context.Context, raw []byte) (*domain.Attestation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := domain.ValidateSurveyRaw(raw); err != nil {
		return nil, err
	}

	id, err := s.ids.NewID()
	if err != nil {
		return nil, err
	}

	stamped := s.clock.Now()
	hash := domain.NewSurveyContent(raw).Hash()

	sig, err := s.signer.Sign(attestationMessage(id, hash, stamped))
	if err != nil {
		return nil, err
	}

	att := domain.NewAttestation(id, hash, stamped, sig)
	if err := s.repo.Save(ctx, att); err != nil {
		return nil, err
	}

	return new(att), nil
}

func (s *Service) Verify(ctx context.Context, id domain.AttestationID) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	att, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return s.signer.Verify(attestationMessage(att.ID, att.Hash, att.Stamped), att.Signature)
}

func attestationMessage(id domain.AttestationID, hash domain.ContentHash, stamped time.Time) []byte {
	return append(append([]byte(id), hash.Bytes()...), stamped.UTC().Format(time.RFC3339Nano)...)
}
