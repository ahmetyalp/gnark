package ecdsa_gkr

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{scalarMulStepsHint}
}

func scalarMulStepsHint(mod *big.Int, inputs, outputs []*big.Int) error {
	// first is scalar
	// second second is X
	// third is Y
	// returns 6*len(bits) (resX, resY, resZ, accX, accY, accZ)
	if len(inputs) != 3 {
		return fmt.Errorf("expecting three inputs")
	}
	scalar, PX, PY := inputs[0], inputs[1], inputs[2]
	if len(outputs)%6 != 0 {
		return fmt.Errorf("expecting nb of outputs to divide 6")
	}
	nbBits := len(outputs) / 6
	if scalar.BitLen() > nbBits {
		return fmt.Errorf("scalar has more bits than output size")
	}
	accumulator := new(G1ProjectiveNative)
	accumulator.X.SetBigInt(PX)
	accumulator.Y.SetBigInt(PY)
	accumulator.Z.SetInt64(1)
	res := NewG1ProjectiveNative()
	for i := 0; i < nbBits; i++ {
		bit := scalar.Bit(i)
		res, accumulator = DoubleAndAddProjectiveNative(uint64(bit), res, accumulator)
		res.X.BigInt(outputs[6*i+0])
		res.Y.BigInt(outputs[6*i+1])
		res.Z.BigInt(outputs[6*i+2])
		accumulator.X.BigInt(outputs[6*i+3])
		accumulator.Y.BigInt(outputs[6*i+4])
		accumulator.Z.BigInt(outputs[6*i+5])
	}

	return nil
}
