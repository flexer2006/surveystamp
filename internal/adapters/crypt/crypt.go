package crypt

import (
	"crypto/ed25519"
	"errors"
	"io"
	"slices"

	"github.com/flexer2006/surveystamp/internal/domain"
	"github.com/flexer2006/surveystamp/internal/ports"
)

var ErrInvalidKey = errors.New("invalid ed25519 private key")

type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

var _ ports.Signer = (*Signer)(nil)

func New(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}

	priv = ed25519.NewKeyFromSeed(priv.Seed())

	return new(Signer{
		priv: priv,
		pub:  ed25519.PublicKey(slices.Clone(priv[ed25519.SeedSize:])),
	}), nil
}

func Generate(random io.Reader) (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, err
	}

	return New(priv)
}

func (s *Signer) Sign(msg []byte) (domain.Signature, error) {
	return domain.NewSignature(ed25519.Sign(s.priv, msg)), nil
}

func (s *Signer) Verify(msg []byte, sig domain.Signature) error {
	if err := domain.ValidateSignature(sig); err != nil {
		return err
	}

	if !ed25519.Verify(s.pub, msg, sig) {
		return domain.ErrInvalidSignature
	}

	return nil
}
