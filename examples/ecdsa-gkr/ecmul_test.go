package ecdsa_gkr

import (
	"crypto/rand"
	"fmt"
	stdhash "hash"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr_secq256k1 "github.com/consensys/gnark-crypto/ecc/secq256k1/fr"
	secq256k1mimc "github.com/consensys/gnark-crypto/ecc/secq256k1/fr/mimc"
	"github.com/consensys/gnark/constraint"
	secq256k1r1cs "github.com/consensys/gnark/constraint/secq256k1"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

func init() {
	secq256k1r1cs.RegisterHashBuilder("mimc", func() stdhash.Hash {
		return secq256k1mimc.NewMiMC()
	})
	hash.Register("mimc", func(api frontend.API) (hash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	})
}

type EcAddCircuit struct {
	InputX []frontend.Variable
	InputY []frontend.Variable

	ExpectedX []frontend.Variable
	ExpectedY []frontend.Variable

	nbIters int
}

func (c *EcAddCircuit) Define(api frontend.API) error {
	g := gkr.NewApi()
	P, err := NewG1Projective(g, c.InputX, c.InputY)
	if err != nil {
		return err
	}
	for i := 0; i < c.nbIters; i++ {
		P = AddProjective(g, P, P)
	}
	solution, err := g.Solve(api)
	if err != nil {
		return fmt.Errorf("gkr solve: %w", err)
	}
	resX, resY := ExportAffine(api, solution, P)
	for i := 0; i < len(c.ExpectedX); i++ {
		api.AssertIsEqual(resX[i], c.ExpectedX[i])
		api.AssertIsEqual(resY[i], c.ExpectedY[i])
	}
	return solution.Verify("mimc")
}

func TestEcAdd(t *testing.T) {
	nbInstances := 1 << 1
	nbIters := 1
	assert := test.NewAssert(t)

	circuitGKR := EcAddCircuit{
		InputX:    make([]frontend.Variable, nbInstances),
		InputY:    make([]frontend.Variable, nbInstances),
		ExpectedX: make([]frontend.Variable, nbInstances),
		ExpectedY: make([]frontend.Variable, nbInstances),
		nbIters:   nbIters,
	}

	ccs1, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), r1cs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	_ = ccs1
	ccs2, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	_ = ccs2

	_, G := secp256k1.Generators()
	var acc secp256k1.G1Affine
	acc.Set(&G)
	assignment := EcAddCircuit{
		InputX:    make([]frontend.Variable, nbInstances),
		InputY:    make([]frontend.Variable, nbInstances),
		ExpectedX: make([]frontend.Variable, nbInstances),
		ExpectedY: make([]frontend.Variable, nbInstances),
		nbIters:   nbIters,
	}
	for i := 0; i < nbInstances; i++ {
		assignment.InputX[i] = (fr_secq256k1.Element)(acc.X)
		assignment.InputY[i] = (fr_secq256k1.Element)(acc.Y)
		var res secp256k1.G1Affine
		res.Set(&acc)
		for j := 0; j < nbIters; j++ {
			res.Add(&res, &res)
		}
		assignment.ExpectedX[i] = (fr_secq256k1.Element)(res.X)
		assignment.ExpectedY[i] = (fr_secq256k1.Element)(res.Y)
		acc.Add(&acc, &G)
	}
	w, err := frontend.NewWitness(&assignment, ecc.SECQ256K1.ScalarField())
	assert.NoError(err)
	err = ccs2.IsSolved(w)
	assert.NoError(err)
}

type EcDoubleCircuit struct {
	InputX []frontend.Variable
	InputY []frontend.Variable

	ExpectedX []frontend.Variable
	ExpectedY []frontend.Variable

	nbIters int
}

func (c *EcDoubleCircuit) Define(api frontend.API) error {
	g := gkr.NewApi()
	P, err := NewG1Projective(g, c.InputX, c.InputY)
	if err != nil {
		return err
	}
	for i := 0; i < c.nbIters; i++ {
		P = DoubleProjective(g, P)
	}
	solution, err := g.Solve(api)
	if err != nil {
		return fmt.Errorf("gkr solve: %w", err)
	}
	resX, resY := ExportAffine(api, solution, P)
	for i := 0; i < len(c.ExpectedX); i++ {
		api.AssertIsEqual(resX[i], c.ExpectedX[i])
		api.AssertIsEqual(resY[i], c.ExpectedY[i])
	}
	return solution.Verify("mimc")
}

func TestEcDouble(t *testing.T) {
	nbInstances := 1 << 1
	nbIters := 1
	assert := test.NewAssert(t)

	circuitGKR := EcDoubleCircuit{
		InputX:    make([]frontend.Variable, nbInstances),
		InputY:    make([]frontend.Variable, nbInstances),
		ExpectedX: make([]frontend.Variable, nbInstances),
		ExpectedY: make([]frontend.Variable, nbInstances),
		nbIters:   nbIters,
	}

	ccs1, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), r1cs.NewBuilder, &circuitGKR, frontend.WithCapacity(10_000_000), frontend.WithCompressThreshold(100))
	assert.NoError(err)
	_ = ccs1
	ccs2, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	_ = ccs2

	_, G := secp256k1.Generators()
	var acc secp256k1.G1Affine
	acc.Set(&G)
	assignment := EcDoubleCircuit{
		InputX:    make([]frontend.Variable, nbInstances),
		InputY:    make([]frontend.Variable, nbInstances),
		ExpectedX: make([]frontend.Variable, nbInstances),
		ExpectedY: make([]frontend.Variable, nbInstances),
		nbIters:   nbIters,
	}
	for i := 0; i < nbInstances; i++ {
		assignment.InputX[i] = (fr_secq256k1.Element)(acc.X)
		assignment.InputY[i] = (fr_secq256k1.Element)(acc.Y)
		var res secp256k1.G1Affine
		res.Set(&acc)
		for j := 0; j < nbIters; j++ {
			res.Double(&res)
		}
		assignment.ExpectedX[i] = (fr_secq256k1.Element)(res.X)
		assignment.ExpectedY[i] = (fr_secq256k1.Element)(res.Y)
		acc.Add(&acc, &G)
	}
	w, err := frontend.NewWitness(&assignment, ecc.SECQ256K1.ScalarField())
	assert.NoError(err)
	err = ccs2.IsSolved(w)
	assert.NoError(err)
}

type EcScalarMulCircuit struct {
	InputX  []frontend.Variable
	InputY  []frontend.Variable
	Scalars []frontend.Variable

	ExpectedX []frontend.Variable
	ExpectedY []frontend.Variable

	nbScalarBits int
}

func (c *EcScalarMulCircuit) Define(api frontend.API) error {
	g := gkr.NewApi()
	P, err := NewG1Projective(g, c.InputX, c.InputY)
	if err != nil {
		return err
	}
	// outer array indices of bits, inner slice bit of the corresponding instance
	scalarsBits := make([][]frontend.Variable, c.nbScalarBits)
	for i := 0; i < c.nbScalarBits; i++ {
		scalarsBits[i] = make([]frontend.Variable, len(c.InputX))
	}
	for i := range c.Scalars {
		sbts := bits.ToBinary(api, c.Scalars[i], bits.WithNbDigits(c.nbScalarBits))
		for j := range scalarsBits {
			scalarsBits[j][i] = sbts[j]
		}
	}
	scalarBits := make([]constraint.GkrVariable, len(scalarsBits))
	for i := range scalarBits {
		scalarBits[i], err = g.Import(scalarsBits[i])
		if err != nil {
			return err
		}
	}
	res, err := NewG1Zero(g, len(c.InputX))
	if err != nil {
		return err
	}
	accumulator := P
	for _, b := range scalarBits {
		res, accumulator = DoubleAndAddProjective(g, b, res, accumulator)
	}
	solution, err := g.Solve(api)
	if err != nil {
		return fmt.Errorf("gkr solve: %w", err)
	}
	resX, resY := ExportAffine(api, solution, res)
	for i := 0; i < len(c.ExpectedX); i++ {
		api.AssertIsEqual(resX[i], c.ExpectedX[i])
		api.AssertIsEqual(resY[i], c.ExpectedY[i])
	}
	return solution.Verify("mimc")
}

func TestEcScalarMul(t *testing.T) {
	nbInstances := 1 << 1
	nbBits := 2
	assert := test.NewAssert(t)

	circuitGKR := EcScalarMulCircuit{
		InputX:       make([]frontend.Variable, nbInstances),
		InputY:       make([]frontend.Variable, nbInstances),
		Scalars:      make([]frontend.Variable, nbInstances),
		ExpectedX:    make([]frontend.Variable, nbInstances),
		ExpectedY:    make([]frontend.Variable, nbInstances),
		nbScalarBits: nbBits,
	}
	ccs1, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), r1cs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	_ = ccs1
	ccs2, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	_ = ccs2

	_, G := secp256k1.Generators()
	var acc secp256k1.G1Affine
	acc.Set(&G)
	assignment := EcScalarMulCircuit{
		InputX:       make([]frontend.Variable, nbInstances),
		InputY:       make([]frontend.Variable, nbInstances),
		Scalars:      make([]frontend.Variable, nbInstances),
		ExpectedX:    make([]frontend.Variable, nbInstances),
		ExpectedY:    make([]frontend.Variable, nbInstances),
		nbScalarBits: nbBits,
	}
	bound := big.NewInt(1)
	bound.Lsh(bound, uint(nbBits))
	bound.Sub(bound, big.NewInt(1))
	for i := 0; i < nbInstances; i++ {
		scalar, err := rand.Int(rand.Reader, bound)
		assert.NoError(err)
		scalar.Add(scalar, big.NewInt(1)) // TODO: cannot handle scalar=0 right now
		assignment.Scalars[i] = scalar

		assignment.InputX[i] = (fr_secq256k1.Element)(acc.X)
		assignment.InputY[i] = (fr_secq256k1.Element)(acc.Y)

		var res secp256k1.G1Affine
		res.ScalarMultiplication(&acc, scalar)
		assignment.ExpectedX[i] = (fr_secq256k1.Element)(res.X)
		assignment.ExpectedY[i] = (fr_secq256k1.Element)(res.Y)

		acc.Add(&acc, &G)
	}
	w, err := frontend.NewWitness(&assignment, ecc.SECQ256K1.ScalarField())
	assert.NoError(err)
	err = ccs2.IsSolved(w)
	assert.NoError(err)
}

type EcScalarMulWideCircuit struct {
	InputX  []frontend.Variable
	InputY  []frontend.Variable
	Scalars []frontend.Variable

	ExpectedX []frontend.Variable
	ExpectedY []frontend.Variable

	nbScalarBits int
}

func (c *EcScalarMulWideCircuit) Define(api frontend.API) error {
	lenInputs := len(c.InputX)
	if lenInputs != len(c.InputY) || lenInputs != len(c.Scalars) {
		return fmt.Errorf("inputs length mismatch")
	}
	allBits := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	allResX := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	allResY := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	allResZ := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	allAccX := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	allAccY := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	allAccZ := make([]frontend.Variable, c.nbScalarBits*lenInputs)
	lastResX := make([]frontend.Variable, lenInputs)
	lastResY := make([]frontend.Variable, lenInputs)
	lastResZ := make([]frontend.Variable, lenInputs)
	for i := range c.InputX {
		allAccX[c.nbScalarBits*i] = c.InputX[i]
		allAccY[c.nbScalarBits*i] = c.InputY[i]
		allAccZ[c.nbScalarBits*i] = 1

		allResX[c.nbScalarBits*i] = 0
		allResY[c.nbScalarBits*i] = 1
		allResZ[c.nbScalarBits*i] = 0
	}
	for i := range c.Scalars {
		sbits := bits.ToBinary(api, c.Scalars[i], bits.WithNbDigits(c.nbScalarBits))
		copy(allBits[c.nbScalarBits*i:c.nbScalarBits*(i+1)], sbits)
	}
	for i := range c.InputX {
		res, err := api.NewHint(scalarMulStepsHint, 6*c.nbScalarBits, c.Scalars[i], c.InputX[i], c.InputY[i])
		if err != nil {
			return fmt.Errorf("scalarsteps iteraton %d: %w", i, err)
		}
		for j := 0; j < c.nbScalarBits-1; j++ {
			allResX[i*c.nbScalarBits+j+1] = res[6*j+0]
			allResY[i*c.nbScalarBits+j+1] = res[6*j+1]
			allResZ[i*c.nbScalarBits+j+1] = res[6*j+2]
			allAccX[i*c.nbScalarBits+j+1] = res[6*j+3]
			allAccY[i*c.nbScalarBits+j+1] = res[6*j+4]
			allAccZ[i*c.nbScalarBits+j+1] = res[6*j+5]
		}
		lastResX[i] = res[6*(c.nbScalarBits-1)+0]
		lastResY[i] = res[6*(c.nbScalarBits-1)+1]
		lastResZ[i] = res[6*(c.nbScalarBits-1)+2]
	}
	g := gkr.NewApi()
	resX, err := g.Import(allResX)
	if err != nil {
		return fmt.Errorf("import x: %w", err)
	}
	resY, err := g.Import(allResY)
	if err != nil {
		return fmt.Errorf("import y: %w", err)
	}
	resZ, err := g.Import(allResZ)
	if err != nil {
		return fmt.Errorf("import z: %w", err)
	}
	res := &G1ProjectiveGKR{
		X: resX,
		Y: resY,
		Z: resZ,
	}
	accX, err := g.Import(allAccX)
	if err != nil {
		return fmt.Errorf("import acc x: %w", err)
	}
	accY, err := g.Import(allAccY)
	if err != nil {
		return fmt.Errorf("import acc y: %w", err)
	}
	accZ, err := g.Import(allAccZ)
	if err != nil {
		return fmt.Errorf("import acc z: %w", err)
	}
	acc := &G1ProjectiveGKR{
		X: accX,
		Y: accY,
		Z: accZ,
	}
	bit, err := g.Import(allBits)
	if err != nil {
		return fmt.Errorf("import bits: %w", err)
	}
	daaRes, daaAcc := DoubleAndAddProjective(g, bit, res, acc)
	solution, err := g.Solve(api)
	if err != nil {
		return fmt.Errorf("gkr solve: %w", err)
	}
	natResX := solution.Export(daaRes.X)
	natResY := solution.Export(daaRes.Y)
	natResZ := solution.Export(daaRes.Z)
	natAccX := solution.Export(daaAcc.X)
	natAccY := solution.Export(daaAcc.Y)
	natAccZ := solution.Export(daaAcc.Z)
	for i := 0; i < lenInputs; i++ {
		for j := 0; j < c.nbScalarBits-1; j++ {
			api.AssertIsEqual(natResX[i*c.nbScalarBits+j], allResX[i*c.nbScalarBits+j+1])
			api.AssertIsEqual(natResY[i*c.nbScalarBits+j], allResY[i*c.nbScalarBits+j+1])
			api.AssertIsEqual(natResZ[i*c.nbScalarBits+j], allResZ[i*c.nbScalarBits+j+1])
			api.AssertIsEqual(natAccX[i*c.nbScalarBits+j], allAccX[i*c.nbScalarBits+j+1])
			api.AssertIsEqual(natAccY[i*c.nbScalarBits+j], allAccY[i*c.nbScalarBits+j+1])
			api.AssertIsEqual(natAccZ[i*c.nbScalarBits+j], allAccZ[i*c.nbScalarBits+j+1])
		}
	}
	for i := 0; i < lenInputs; i++ {
		X := api.Div(natResX[(i+1)*c.nbScalarBits-1], natResZ[(i+1)*c.nbScalarBits-1])
		Y := api.Div(natResY[(i+1)*c.nbScalarBits-1], natResZ[(i+1)*c.nbScalarBits-1])
		api.AssertIsEqual(X, c.ExpectedX[i])
		api.AssertIsEqual(Y, c.ExpectedY[i])
	}
	return solution.Verify("mimc")
}

func TestEcScalarMulWide(t *testing.T) {
	nbInstances := 1 << 1
	nbBits := 256
	assert := test.NewAssert(t)

	circuitGKR := EcScalarMulWideCircuit{
		InputX:       make([]frontend.Variable, nbInstances),
		InputY:       make([]frontend.Variable, nbInstances),
		Scalars:      make([]frontend.Variable, nbInstances),
		ExpectedX:    make([]frontend.Variable, nbInstances),
		ExpectedY:    make([]frontend.Variable, nbInstances),
		nbScalarBits: nbBits,
	}
	ccs2, err := frontend.Compile(ecc.SECQ256K1.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)

	_, G := secp256k1.Generators()
	var acc secp256k1.G1Affine
	acc.Set(&G)
	assignment := EcScalarMulWideCircuit{
		InputX:       make([]frontend.Variable, nbInstances),
		InputY:       make([]frontend.Variable, nbInstances),
		Scalars:      make([]frontend.Variable, nbInstances),
		ExpectedX:    make([]frontend.Variable, nbInstances),
		ExpectedY:    make([]frontend.Variable, nbInstances),
		nbScalarBits: nbBits,
	}
	bound := big.NewInt(1)
	bound.Lsh(bound, uint(nbBits))
	bound.Sub(bound, big.NewInt(1))
	for i := 0; i < nbInstances; i++ {
		scalar, err := rand.Int(rand.Reader, bound)
		assert.NoError(err)
		scalar.Add(scalar, big.NewInt(1)) // TODO: cannot handle scalar=0 right now
		assignment.Scalars[i] = scalar

		assignment.InputX[i] = (fr_secq256k1.Element)(acc.X)
		assignment.InputY[i] = (fr_secq256k1.Element)(acc.Y)

		var res secp256k1.G1Affine
		res.ScalarMultiplication(&acc, scalar)
		assignment.ExpectedX[i] = (fr_secq256k1.Element)(res.X)
		assignment.ExpectedY[i] = (fr_secq256k1.Element)(res.Y)

		acc.Add(&acc, &G)
	}

	w, err := frontend.NewWitness(&assignment, ecc.SECQ256K1.ScalarField())
	assert.NoError(err)
	err = ccs2.IsSolved(w)
	assert.NoError(err)
}
