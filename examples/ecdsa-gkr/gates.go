package ecdsa_gkr

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
)

type coordT int

const (
	xCoord coordT = iota
	yCoord
	zCoord
)

func init() {
	gkr.Gates["select"] = SelectGate{}
	gkr.Gates["doubleX"] = DoubleGate{coordT: xCoord}
	gkr.Gates["doubleY"] = DoubleGate{coordT: yCoord}
	gkr.Gates["doubleZ"] = DoubleGate{coordT: zCoord}
	gkr.Gates["addX"] = AddGate{coordT: xCoord}
	gkr.Gates["addY"] = AddGate{coordT: yCoord}
	gkr.Gates["addZ"] = AddGate{coordT: zCoord}
}

type SelectGate struct{}

func (g SelectGate) Evaluate(api frontend.API, in ...frontend.Variable) frontend.Variable {
	// the selector variable must already be constrained to be 0-1. We cannot do
	// it inside GKR so will do it out-GKR.
	if len(in) != 3 {
		panic("invalid number of inputs")
	}
	v := api.Sub(in[1], in[2])
	v = api.Mul(in[0], v)
	return api.Add(v, in[2])
}

func (SelectGate) Degree() int { return 5 }

type DoubleGate struct {
	coordT
}

func (g DoubleGate) Evaluate(api frontend.API, in ...frontend.Variable) frontend.Variable {
	if len(in) != 3 {
		panic("invalid number of inputs")
	}
	X, Y, Z := in[0], in[1], in[2]
	t0 := api.Mul(Y, Y)
	Z3 := api.Add(t0, t0)
	Z3 = api.Add(Z3, Z3)
	Z3 = api.Add(Z3, Z3)
	t1 := api.Mul(Y, Z)
	t2 := api.Mul(Z, Z)
	t2 = api.Mul(21, t2)
	X3 := api.Mul(t2, Z3)
	Y3 := api.Add(t0, t2)
	Z3 = api.Mul(t1, Z3)
	t1 = api.Add(t2, t2)
	t2 = api.Add(t1, t2)
	t0 = api.Sub(t0, t2)
	Y3 = api.Mul(t0, Y3)
	Y3 = api.Add(X3, Y3)
	t1 = api.Mul(X, Y)
	X3 = api.Mul(t0, t1)
	X3 = api.Add(X3, X3)
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

func (DoubleGate) Degree() int { return 10 }

type AddGate struct {
	coordT
}

func (g AddGate) Evaluate(api frontend.API, in ...frontend.Variable) frontend.Variable {
	if len(in) != 6 {
		panic("invalid number of inputs")
	}
	X1, X2, Y1, Y2, Z1, Z2 := in[0], in[1], in[2], in[3], in[4], in[5]

	t0 := api.Mul(X1, X2)
	t1 := api.Mul(Y1, Y2)
	t2 := api.Mul(Z1, Z2)
	t3 := api.Add(X1, Y1)
	t4 := api.Add(X2, Y2)
	t3 = api.Mul(t3, t4)
	t4 = api.Add(t0, t1)
	t3 = api.Sub(t3, t4)
	t4 = api.Add(Y1, Z1)
	X3 := api.Add(Y2, Z2)
	t4 = api.Mul(t4, X3)
	X3 = api.Add(t1, t2)
	t4 = api.Sub(t4, X3)
	X3 = api.Add(X1, Z1)
	Y3 := api.Add(X2, Z2)
	X3 = api.Mul(X3, Y3)
	Y3 = api.Add(t0, t2)
	Y3 = api.Sub(X3, Y3)
	X3 = api.Add(t0, t0)
	t0 = api.Add(X3, t0)
	t2 = api.Mul(21, t2)
	Z3 := api.Add(t1, t2)
	t1 = api.Sub(t1, t2)
	Y3 = api.Mul(21, Y3)
	X3 = api.Mul(t4, Y3)
	t2 = api.Mul(t3, t1)
	X3 = api.Sub(t2, X3)
	Y3 = api.Mul(Y3, t0)
	t1 = api.Mul(t1, Z3)
	Y3 = api.Add(t1, Y3)
	t0 = api.Mul(t0, t3)
	Z3 = api.Mul(Z3, t4)
	Z3 = api.Add(Z3, t0)
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

func (AddGate) Degree() int { return 15 }
