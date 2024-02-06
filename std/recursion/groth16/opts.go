package groth16

import (
	"fmt"

	"github.com/consensys/gnark/std/hash"
)

type verifierCfg struct {
	HashToFieldFn hash.FieldHasher
}

// VerifierOption allows to modify the behaviour of Groth16 verifier.
type VerifierOption func(cfg *verifierCfg) error

// WithVerifierHashToFieldFn changes the hash function used for hashing
// bytes to field. If not set verifier will return an error when
// hashing is required.
func WithVerifierHashToFieldFn(h hash.FieldHasher) VerifierOption {
	return func(cfg *verifierCfg) error {
		cfg.HashToFieldFn = h
		return nil
	}
}

func newCfg(opts ...VerifierOption) (*verifierCfg, error) {
	cfg := new(verifierCfg)
	for i := range opts {
		if err := opts[i](cfg); err != nil {
			return nil, fmt.Errorf("option %d: %w", i, err)
		}
	}
	return cfg, nil
}
