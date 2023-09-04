package ecdsa_gkr

import (
	"fmt"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
)

type G1ProjectiveGKR struct {
	X, Y, Z constraint.GkrVariable
}

func NewG1Projective(g *gkr.API, X, Y []frontend.Variable) (*G1ProjectiveGKR, error) {
	if len(X) != len(Y) {
		return nil, fmt.Errorf("nb of X and Y differ")
	}
	x, err := g.Import(X)
	if err != nil {
		return nil, fmt.Errorf("x: %w", err)
	}
	y, err := g.Import(Y)
	if err != nil {
		return nil, fmt.Errorf("y: %w", err)
	}
	ones := make([]frontend.Variable, len(X))
	for i := range ones {
		ones[i] = 1
	}
	z, err := g.Import(ones)
	if err != nil {
		return nil, fmt.Errorf("z: %w", err)
	}
	return &G1ProjectiveGKR{
		X: x,
		Y: y,
		Z: z,
	}, nil
}

func NewG1Zero(g *gkr.API, length int) (*G1ProjectiveGKR, error) {
	zeros := make([]frontend.Variable, length)
	for i := range zeros {
		zeros[i] = 0
	}
	gkrZeros, err := g.Import(zeros)
	if err != nil {
		return nil, fmt.Errorf("z: %w", err)
	}
	ones := make([]frontend.Variable, length)
	for i := range ones {
		ones[i] = 1
	}
	gkrOnes, err := g.Import(ones)
	if err != nil {
		return nil, fmt.Errorf("z: %w", err)
	}
	return &G1ProjectiveGKR{
		X: gkrZeros,
		Y: gkrOnes,
		Z: gkrZeros,
	}, nil
}

func ExportAffine(api frontend.API, solution gkr.Solution, P *G1ProjectiveGKR) (X, Y []frontend.Variable) {
	// TODO: division by zero for point at infinity.
	natResX := solution.Export(P.X)
	natResY := solution.Export(P.Y)
	natResZ := solution.Export(P.Z)
	X = make([]frontend.Variable, len(natResX))
	Y = make([]frontend.Variable, len(natResY))
	for i := range natResX {
		X[i] = api.Div(natResX[i], natResZ[i])
		Y[i] = api.Div(natResY[i], natResZ[i])
	}
	return X, Y
}

func AddProjective(g *gkr.API, P, Q *G1ProjectiveGKR) *G1ProjectiveGKR {
	X3 := g.NamedGate("addX", P.X, Q.X, P.Y, Q.Y, P.Z, Q.Z)
	Y3 := g.NamedGate("addY", P.X, Q.X, P.Y, Q.Y, P.Z, Q.Z)
	Z3 := g.NamedGate("addZ", P.X, Q.X, P.Y, Q.Y, P.Z, Q.Z)
	return &G1ProjectiveGKR{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func DoubleProjective(g *gkr.API, P *G1ProjectiveGKR) *G1ProjectiveGKR {
	X3 := g.NamedGate("doubleX", P.X, P.Y, P.Z)
	Y3 := g.NamedGate("doubleY", P.X, P.Y, P.Z)
	Z3 := g.NamedGate("doubleZ", P.X, P.Y, P.Z)
	return &G1ProjectiveGKR{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func SelectProjective(g *gkr.API, selector constraint.GkrVariable, ifTrue, ifFalse *G1ProjectiveGKR) *G1ProjectiveGKR {
	X3 := g.NamedGate("select", selector, ifTrue.X, ifFalse.X)
	Y3 := g.NamedGate("select", selector, ifTrue.Y, ifFalse.Y)
	Z3 := g.NamedGate("select", selector, ifTrue.Z, ifFalse.Z)
	return &G1ProjectiveGKR{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func DoubleAndAddProjective(g *gkr.API, currentBit constraint.GkrVariable, prevResult, prevAccumulator *G1ProjectiveGKR) (result, accumulator *G1ProjectiveGKR) {
	A := AddProjective(g, prevAccumulator, prevResult)
	result = SelectProjective(g, currentBit, A, prevResult)
	accumulator = DoubleProjective(g, prevAccumulator)
	return
}
