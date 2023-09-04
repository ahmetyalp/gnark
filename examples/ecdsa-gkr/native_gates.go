package ecdsa_gkr

import (
	fr_secq256k1 "github.com/consensys/gnark-crypto/ecc/secq256k1/fr"
	crypto_gkr "github.com/consensys/gnark-crypto/ecc/secq256k1/fr/gkr"
)

// TODO: i'm not sure if the degree of gate is number of muls or nbInputs+nbMuls

var (
	addXNative = AddGateNative{coordT: xCoord}
	addYNative = AddGateNative{coordT: yCoord}
	addZNative = AddGateNative{coordT: zCoord}

	doubleXNative = DoubleGateNative{coordT: xCoord}
	doubleYNative = DoubleGateNative{coordT: yCoord}
	doubleZNative = DoubleGateNative{coordT: zCoord}

	selectNative = SelectGateNative{}
)

func init() {
	crypto_gkr.Gates["select"] = selectNative
	crypto_gkr.Gates["doubleX"] = doubleXNative
	crypto_gkr.Gates["doubleY"] = doubleYNative
	crypto_gkr.Gates["doubleZ"] = doubleZNative
	crypto_gkr.Gates["addX"] = addXNative
	crypto_gkr.Gates["addY"] = addYNative
	crypto_gkr.Gates["addZ"] = addZNative
}

type SelectGateNative struct{}

func (SelectGateNative) Evaluate(in ...fr_secq256k1.Element) fr_secq256k1.Element {
	var res fr_secq256k1.Element
	res.Sub(&in[1], &in[2])
	res.Mul(&in[0], &res)
	res.Add(&res, &in[2])
	return res
}
func (SelectGateNative) Degree() int { return 5 }

type DoubleGateNative struct {
	coordT
}

func (g DoubleGateNative) Evaluate(in ...fr_secq256k1.Element) fr_secq256k1.Element {
	X, Y, Z := in[0], in[1], in[2]
	var t0, t1, t2, X3, Y3, Z3 fr_secq256k1.Element
	twentyOne := fr_secq256k1.NewElement(21)

	t0.Mul(&Y, &Y)
	Z3.Add(&t0, &t0)
	Z3.Add(&Z3, &Z3)
	Z3.Add(&Z3, &Z3)
	t1.Mul(&Y, &Z)
	t2.Mul(&Z, &Z)
	t2.Mul(&twentyOne, &t2)
	X3.Mul(&t2, &Z3)
	Y3.Add(&t0, &t2)
	Z3.Mul(&t1, &Z3)
	t1.Add(&t2, &t2)
	t2.Add(&t1, &t2)
	t0.Sub(&t0, &t2)
	Y3.Mul(&t0, &Y3)
	Y3.Add(&X3, &Y3)
	t1.Mul(&X, &Y)
	X3.Mul(&t0, &t1)
	X3.Add(&X3, &X3)
	switch g.coordT {
	case xCoord:
		return X3
	case yCoord:
		return Y3
	case zCoord:
		return Z3
	default:
		panic("wrong instruction")
	}
}

func (DoubleGateNative) Degree() int { return 10 }

type AddGateNative struct {
	coordT
}

func (g AddGateNative) Evaluate(in ...fr_secq256k1.Element) fr_secq256k1.Element {
	X1, X2, Y1, Y2, Z1, Z2 := in[0], in[1], in[2], in[3], in[4], in[5]

	var t0, t1, t2, t3, t4 fr_secq256k1.Element
	var X3, Y3, Z3 fr_secq256k1.Element
	twentyOne := fr_secq256k1.NewElement(21)

	t0.Mul(&X1, &X2)
	t1.Mul(&Y1, &Y2)
	t2.Mul(&Z1, &Z2)
	t3.Add(&X1, &Y1)
	t4.Add(&X2, &Y2)
	t3.Mul(&t3, &t4)
	t4.Add(&t0, &t1)
	t3.Sub(&t3, &t4)
	t4.Add(&Y1, &Z1)
	X3.Add(&Y2, &Z2)
	t4.Mul(&t4, &X3)
	X3.Add(&t1, &t2)
	t4.Sub(&t4, &X3)
	X3.Add(&X1, &Z1)
	Y3.Add(&X2, &Z2)
	X3.Mul(&X3, &Y3)
	Y3.Add(&t0, &t2)
	Y3.Sub(&X3, &Y3)
	X3.Add(&t0, &t0)
	t0.Add(&X3, &t0)
	t2.Mul(&twentyOne, &t2)
	Z3.Add(&t1, &t2)
	t1.Sub(&t1, &t2)
	Y3.Mul(&twentyOne, &Y3)
	X3.Mul(&t4, &Y3)
	t2.Mul(&t3, &t1)
	X3.Sub(&t2, &X3)
	Y3.Mul(&Y3, &t0)
	t1.Mul(&t1, &Z3)
	Y3.Add(&t1, &Y3)
	t0.Mul(&t0, &t3)
	Z3.Mul(&Z3, &t4)
	Z3.Add(&Z3, &t0)
	switch g.coordT {
	case xCoord:
		return X3
	case yCoord:
		return Y3
	case zCoord:
		return Z3
	default:
		panic("wrong instruction")
	}
}

func (AddGateNative) Degree() int { return 15 }
