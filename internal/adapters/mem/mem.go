package mem

import (
	"context"
	"hash/maphash"
	"slices"
	"sync"

	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/ports"
)

const shardCount = 64

type Repository struct {
	seed   maphash.Seed
	shards [shardCount]shard
}

type shard struct {
	mu sync.Mutex
	m  map[domain.AttestationID]domain.Attestation
}

var _ ports.AttestationRepository = (*Repository)(nil)

func New() *Repository {
	r := new(Repository{seed: maphash.MakeSeed()})
	for i := range r.shards {
		r.shards[i].m = make(map[domain.AttestationID]domain.Attestation)
	}

	return r
}

func (r *Repository) Save(ctx context.Context, attestation domain.Attestation) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s := r.shardFor(attestation.ID)
	s.mu.Lock()
	s.m[attestation.ID] = clone(attestation)
	s.mu.Unlock()

	return nil
}

func (r *Repository) GetByID(ctx context.Context, id domain.AttestationID) (domain.Attestation, error) {
	if err := ctx.Err(); err != nil {
		return domain.Attestation{}, err
	}

	s := r.shardFor(id)
	s.mu.Lock()

	att, ok := s.m[id]
	if ok {
		att = clone(att)
	}
	s.mu.Unlock()

	if !ok {
		return domain.Attestation{}, domain.ErrNotFound
	}

	return att, nil
}

func (r *Repository) shardFor(id domain.AttestationID) *shard {
	return &r.shards[maphash.String(r.seed, string(id))&(shardCount-1)]
}

func clone(a domain.Attestation) domain.Attestation {
	a.Signature = slices.Clone(a.Signature)

	return a
}
