package ecdsa_gkr

import (
	stdhash "hash"
	"math/big"

	secq256k1r1cs "github.com/consensys/gnark/constraint/secq256k1"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// dummyhasherNative is a no-op hasher. Used for measuring the verifier cost
// only as for implementing non-native operations we can use the native hasher.
type dummyhasherNative struct{}
type dummyhasher struct{}

func (h dummyhasherNative) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h dummyhasherNative) Sum(b []byte) []byte {
	var a [32]byte
	c := big.NewInt(12345231214)
	c.FillBytes(a[:])
	return a[:]
}

// Reset resets the Hash to its initial state.
func (h dummyhasherNative) Reset() {

}

// Size returns the number of bytes Sum will return.
func (h dummyhasherNative) Size() int {
	return 32
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (h dummyhasherNative) BlockSize() int {
	panic("not implemented") // TODO: Implement
}

// Sum computes the hash of the internal state of the hash function.
func (h dummyhasher) Sum() frontend.Variable {
	return 12345231214
}

// Write populate the internal state of the hash function with data. The inputs are native field elements.
func (h dummyhasher) Write(data ...frontend.Variable) {

}

// Reset empty the internal state and put the intermediate state to zero.
func (h dummyhasher) Reset() {

}

func init() {
	secq256k1r1cs.RegisterHashBuilder("dummy", func() stdhash.Hash {
		return dummyhasherNative{}
	})
	hash.Register("dummy", func(api frontend.API) (hash.FieldHasher, error) {
		return dummyhasher{}, nil
	})
}
