package domain

import (
	"crypto/sha256"
	"slices"
)

func (c SurveyContent) Canonical() []byte { return slices.Clone(c.raw) }
func (c SurveyContent) Hash() ContentHash { return ContentHash{digest: sha256.Sum256(c.Canonical())} }

func (h ContentHash) Bytes() []byte                    { return slices.Clone(h.digest[:]) }
func (h ContentHash) Equal(candidate ContentHash) bool { return h == candidate }
