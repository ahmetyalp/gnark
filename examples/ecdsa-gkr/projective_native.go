package ecdsa_gkr

import (
	fr_secq256k1 "github.com/consensys/gnark-crypto/ecc/secq256k1/fr"
)

type G1ProjectiveNative struct {
	X, Y, Z fr_secq256k1.Element
}

func NewG1ProjectiveNative() *G1ProjectiveNative {
	return &G1ProjectiveNative{
		X: fr_secq256k1.NewElement(0),
		Y: fr_secq256k1.NewElement(1),
		Z: fr_secq256k1.NewElement(0),
	}
}

func AddProjectiveNative(P, Q *G1ProjectiveNative) *G1ProjectiveNative {
	X3 := addXNative.Evaluate(P.X, Q.X, P.Y, Q.Y, P.Z, Q.Z)
	Y3 := addYNative.Evaluate(P.X, Q.X, P.Y, Q.Y, P.Z, Q.Z)
	Z3 := addZNative.Evaluate(P.X, Q.X, P.Y, Q.Y, P.Z, Q.Z)
	return &G1ProjectiveNative{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func DoubleProjectiveNative(P *G1ProjectiveNative) *G1ProjectiveNative {
	X3 := doubleXNative.Evaluate(P.X, P.Y, P.Z)
	Y3 := doubleYNative.Evaluate(P.X, P.Y, P.Z)
	Z3 := doubleZNative.Evaluate(P.X, P.Y, P.Z)
	return &G1ProjectiveNative{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func SelectProjectiveNative(selector uint64, ifTrue, ifFalse *G1ProjectiveNative) *G1ProjectiveNative {
	v := fr_secq256k1.NewElement(selector)
	X3 := selectNative.Evaluate(v, ifTrue.X, ifFalse.X)
	Y3 := selectNative.Evaluate(v, ifTrue.Y, ifFalse.Y)
	Z3 := selectNative.Evaluate(v, ifTrue.Z, ifFalse.Z)
	return &G1ProjectiveNative{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func DoubleAndAddProjectiveNative(currentBit uint64, prevResult, prevAccumulator *G1ProjectiveNative) (result, accumulator *G1ProjectiveNative) {
	A := AddProjectiveNative(prevAccumulator, prevResult)
	result = SelectProjectiveNative(currentBit, A, prevResult)
	accumulator = DoubleProjectiveNative(prevAccumulator)
	return
}

func NormalizeNative(P *G1ProjectiveNative) *G1ProjectiveNative {
	if P.Z.IsZero() {
		return P
	}
	var X, Y fr_secq256k1.Element
	X.Div(&P.X, &P.Z)
	Y.Div(&P.Y, &P.Z)
	return &G1ProjectiveNative{
		X: X,
		Y: Y,
		Z: fr_secq256k1.One(),
	}
}
