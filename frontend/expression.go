/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package frontend

import (
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/backend/r1cs/term"
)

// Expression [of constraints] represents the lowest level of circuit design
// Inspired from ZCash specs
// When designing a circuit, one has access to (in increasing order of level):
// 	- constraint that generates new inputs (basic constraints)
// 	- gadgets (built out of basic constraints, such as boolean constraint)
// An Expression is a mathematical Expression in given number of variables that can be evaluated,
// and whose result is another wire. At most, quadratic operations appear in an Expression.
// The goal of an Expression is to exploit the R1cs struct in all way possible.
// For instance, a selection constraint b(y-x)=(x-z) (where z is the ouput), corresponds
// to the Expression x-b(y-x), because evaluating this Expression yields z.
// Though x-b(y-x) is not a r1cs: to convert it to a r1cs constraint, one needs a
// function toR1CS.
// Ex: toR1CS(x-b(y-x), z) -> b(y-x)=(x-z), it is now a R1cs.
// To evaluate an Expression (for the computational graph to instantiate the variables),
// one also needs a function Compute.
// For the computatinal graph one needs to know which wires are used in a given Expression
// The bound in the number of expressions is only limited by the fact that we use a r1cs system.
type expression interface {
	consumeWires(consumedWires map[int]struct{})                                     // used during the conversion to r1cs: tells what variables are consumed (useful for the post ordering)
	toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, wire int) r1cs.R1C // turns an expression into a r1cs (ex: toR1cs on a selection constraint x-b(y-x) yields: b(y-x)=z-x)
	// string() string                                    // implement string interface
}

// Multi Output expression
type moExpression interface {
	setConstraintID(cs *CS, id int64) // set the wire's constraintID to n for the wires that don't have this field set yet
	expression
}

type operationType uint8

const (
	mul operationType = iota
	div
)

// singleTermExpression expression of type coef*wire
type singleTermExpression struct {
	term.Term
}

func (t *singleTermExpression) consumeWires(consumedWires map[int]struct{}) {
	consumedWires[t.ConstraintID()] = struct{}{}
}

func (t *singleTermExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, wire int) r1cs.R1C {
	var L, R, O r1cs.LinearExpression
	isDivision := t.IsDivision()
	if !isDivision {
		L = r1cs.LinearExpression{
			term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt()),
		}

		R = r1cs.LinearExpression{
			cs.term(oneWireIDOrdered, *bOne),
		}

		O = r1cs.LinearExpression{
			cs.term(cs.Wires[wire].WireIDOrdering, *bOne),
		}
	} else {
		L = r1cs.LinearExpression{
			term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt()),
		}

		R = r1cs.LinearExpression{
			cs.term(cs.Wires[wire].WireIDOrdering, *bOne),
		}

		O = r1cs.LinearExpression{
			cs.term(oneWireIDOrdered, *bOne),
		}
	}

	return r1cs.R1C{
		L:      L,
		R:      R,
		O:      O,
		Solver: backend.SingleOutput,
	}
}

func (t singleTermExpression) string() string {
	res := "not implemeted"
	// tmp := t.Coeff //.ToRegular()
	// if t.Operation == mul {
	// 	res = res + tmp.String() // TODO + t.ConstraintID().String()
	// } else {
	// 	res = res + "(" + res + tmp.String() + /* TODO t.ConstraintID().String() +*/ ")**-1"
	// }
	return res
}

// linearExpression linear expression of constraints
type linearExpression []term.Term

func (l *linearExpression) consumeWires(consumedWires map[int]struct{}) {
	for _, t := range *l {
		consumedWires[t.ConstraintID()] = struct{}{}
	}
}

func (l *linearExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	left := r1cs.LinearExpression{}
	for _, t := range *l {
		lwt := term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt())
		left = append(left, lwt)
	}

	right := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bOne),
	}

	o := r1cs.LinearExpression{
		cs.term(cs.Wires[w].WireIDOrdering, *bOne),
	}

	return r1cs.R1C{L: left, R: right, O: o, Solver: backend.SingleOutput}
}

func (l *linearExpression) string() string {
	res := ""
	for _, t := range *l {
		res += t.String()
		res += "+"
	}
	res = res[:len(res)-1]
	return res
}

// quadraticExpression quadratic expression of constraints
type quadraticExpression struct {
	left, right linearExpression // in case of division, left is the denominator, right the numerator
	operation   operationType    // type op operation (left*right or right/left)
}

func (q *quadraticExpression) consumeWires(consumedWires map[int]struct{}) {
	q.left.consumeWires(consumedWires)
	q.right.consumeWires(consumedWires)
}

func (q *quadraticExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	switch q.operation {
	case mul:
		L := r1cs.LinearExpression{}
		for _, t := range q.left {
			L = append(L, term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt()))
		}

		R := r1cs.LinearExpression{}
		for _, t := range q.right {
			R = append(R, term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt()))
		}

		O := r1cs.LinearExpression{
			cs.term(cs.Wires[w].WireIDOrdering, *bOne),
		}

		return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
	case div:
		L := r1cs.LinearExpression{}

		for _, t := range q.left {
			L = append(L, term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt()))
		}

		R := r1cs.LinearExpression{
			cs.term(cs.Wires[w].WireIDOrdering, *bOne),
		}

		O := r1cs.LinearExpression{}
		for _, t := range q.right {
			O = append(O, term.NewTerm(cs.Wires[t.ConstraintID()].WireIDOrdering, t.CoeffID(), t.SpecialValueInt()))
		}

		return r1cs.R1C{L: L, R: R, O: O}
	default:
		panic("unimplemented operation")
	}
}

func (q *quadraticExpression) string() string {
	var res string
	if q.operation == mul {
		res = "("
		res = res + q.left.string() + ")*(" + q.right.string() + ")"
	} else {
		res = res + q.right.string() + "*" + q.left.string() + "^-1"
		return res
	}
	return res
}

// selectExpression expression used to select a value according to a boolean evaluation
// b(y-x)=(y-z)
type selectExpression struct {
	b, x, y int
}

func (s *selectExpression) consumeWires(consumedWires map[int]struct{}) {
	consumedWires[s.b] = struct{}{}
	consumedWires[s.x] = struct{}{}
	consumedWires[s.y] = struct{}{}
}

func (s *selectExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg(&one)

	L := r1cs.LinearExpression{
		cs.term(cs.Wires[s.b].WireIDOrdering, one),
	}

	R := r1cs.LinearExpression{
		cs.term(cs.Wires[s.y].WireIDOrdering, one),
		cs.term(cs.Wires[s.x].WireIDOrdering, minusOne),
	}

	O := r1cs.LinearExpression{
		cs.term(cs.Wires[s.y].WireIDOrdering, one),
		cs.term(cs.Wires[w].WireIDOrdering, minusOne),
	}
	return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
}

// func (s *selectExpression) string() string {
// 	res := ""
// 	res = res + s.x.String() + "-" + s.b.String()
// 	res = res + "*(" + s.y.String() + "-" + s.x.String() + ")"
// 	return res
// }

// xorExpression expression used to compute the xor between two variables
// (2*a)b = (a+b-c)
type xorExpression struct {
	a, b int
}

func (x *xorExpression) consumeWires(consumedWires map[int]struct{}) {
	consumedWires[x.a] = struct{}{}
	consumedWires[x.b] = struct{}{}
}

func (x *xorExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	L := r1cs.LinearExpression{
		cs.term(cs.Wires[x.a].WireIDOrdering, *bTwo),
	}

	R := r1cs.LinearExpression{
		cs.term(cs.Wires[x.b].WireIDOrdering, *bOne),
	}

	O := r1cs.LinearExpression{
		cs.term(cs.Wires[x.a].WireIDOrdering, *bOne),
		cs.term(cs.Wires[x.b].WireIDOrdering, *bOne),
		cs.term(cs.Wires[w].WireIDOrdering, *bMinusOne),
	}

	return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
}

// func (x *xorExpression) string() string {
// 	res := ""
// 	res = res + x.a.String() + "+" + x.b.String()
// 	res = res + "-2*" + x.a.String() + "*" + x.b.String()
// 	return res
// }

// unpackExpression expression used to unpack a variable in binary (bits[i]*2^i = res)
type unpackExpression struct {
	bits []int
	res  int
}

func (u *unpackExpression) consumeWires(consumedWires map[int]struct{}) {
	consumedWires[u.res] = struct{}{}
}

func (u *unpackExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	// L
	left := r1cs.LinearExpression{}
	acc := *bOne
	for _, b := range u.bits {
		var tmp big.Int
		tmp.Set(&acc)
		left = append(left, cs.term(cs.Wires[b].WireIDOrdering, tmp))
		acc.Mul(&acc, bTwo)
	}

	// R
	right := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bOne),
	}

	// O
	o := r1cs.LinearExpression{
		cs.term(cs.Wires[u.res].WireIDOrdering, *bOne),
	}

	return r1cs.R1C{L: left, R: right, O: o, Solver: backend.BinaryDec}
}

func (u *unpackExpression) setConstraintID(cs *CS, n int64) {
	for _, w := range u.bits {
		ww := cs.Wires[w]
		ww.ConstraintID = n
		cs.Wires[w] = ww
	}
}

// func (u *unpackExpression) string() string {

// 	res := ""
// 	for i, b := range u.bits {
// 		res += b.String() + "*2^" + strconv.Itoa(i) + "+"
// 	}
// 	res = res[:len(res)-1]
// 	res += " = " + u.res.String()
// 	return res
// }

// packing expression
type packExpression struct {
	bits []int
}

func (p *packExpression) consumeWires(consumedWires map[int]struct{}) {
	for _, w := range p.bits {
		consumedWires[w] = struct{}{}
	}
}

func (p *packExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	// L
	left := r1cs.LinearExpression{}
	acc := *bOne
	for _, b := range p.bits {
		var tmp big.Int
		tmp.Set(&acc)
		lwtl := cs.term(cs.Wires[b].WireIDOrdering, tmp)
		left = append(left, lwtl)
		acc.Mul(&acc, bTwo)
	}

	// R
	right := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bOne),
	}

	// O
	o := r1cs.LinearExpression{
		cs.term(cs.Wires[w].WireIDOrdering, *bOne),
	}

	return r1cs.R1C{L: left, R: right, O: o, Solver: backend.SingleOutput}
}

// func (p *packExpression) string() string {
// 	res := ""
// 	for i, b := range p.bits {
// 		res += b.String() + "*2^" + strconv.Itoa(i) + "+"
// 	}
// 	res = res[:len(res)-1]
// 	return res
// }

// boolean constraint
type booleanExpression struct {
	b int
}

func (b *booleanExpression) consumeWires(consumedWires map[int]struct{}) {
}

func (b *booleanExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	L := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bOne),
		cs.term(cs.Wires[b.b].WireIDOrdering, *bMinusOne),
	}

	R := r1cs.LinearExpression{
		cs.term(cs.Wires[b.b].WireIDOrdering, *bOne),
	}

	O := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bZero),
	}

	return r1cs.R1C{L: L, R: R, O: O}
}

// func (b *booleanExpression) string() string {

// 	res := "(1-"
// 	res = res + b.b.String() + ")*(" + b.b.String() + ")=0"
// 	return res
// }

// equalExpression a - b = 0
type equalExpression struct {
	a, b int
}

func (e *equalExpression) consumeWires(consumedWires map[int]struct{}) {
}

func (e *equalExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	L := r1cs.LinearExpression{
		cs.term(cs.Wires[e.a].WireIDOrdering, *bOne),
		cs.term(cs.Wires[e.b].WireIDOrdering, *bMinusOne),
	}

	R := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bOne),
	}

	O := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bZero),
	}

	return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
}

// eqConstExp wire is equal to a constant
type equalConstantExpression struct {
	a int
	v big.Int
}

func (e *equalConstantExpression) consumeWires(consumedWires map[int]struct{}) {}

func (e *equalConstantExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	// L
	L := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, e.v),
	}

	// R
	R := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, *bOne),
	}

	// O
	// TODO that's sa bit dirty.
	// if a is set, we use a as a wire
	// if not we use the resulting wire w
	ww := w
	if e.a != 0 {
		ww = e.a
	}
	O := r1cs.LinearExpression{
		cs.term(cs.Wires[ww].WireIDOrdering, *bOne),
	}

	return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
}

func (e *equalConstantExpression) string() string {
	return e.v.String()
}

// implyExpression implication constraint: if b is 1 then a is 0
type implyExpression struct {
	b, a int
}

func (i *implyExpression) consumeWires(consumedWires map[int]struct{}) {
}

func (i *implyExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {

	var one, minusOne, zero big.Int
	one.SetUint64(1)
	minusOne.Neg(&one)

	L := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, one),
		cs.term(cs.Wires[i.b].WireIDOrdering, minusOne),
		cs.term(cs.Wires[i.a].WireIDOrdering, minusOne),
	}

	R := r1cs.LinearExpression{
		cs.term(cs.Wires[i.a].WireIDOrdering, one),
	}

	O := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, zero),
	}

	return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
}

// func (i *implyExpression) string() string {
// 	res := ""
// 	res = res + "(1 - " + i.b.String() + " - " + i.a.String() + ")*( " + i.a.String() + ")=0"
// 	return res
// }

// lutExpression lookup table constraint, selects the i-th entry in the lookup table where i=2*bit1+bit0
// cf https://z.cash/technology/jubjub/
type lutExpression struct {
	b0, b1      int
	lookuptable [4]big.Int
}

func (win *lutExpression) consumeWires(consumedWires map[int]struct{}) {
	consumedWires[win.b0] = struct{}{}
	consumedWires[win.b1] = struct{}{}
}

func (win *lutExpression) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS, oneWireIDOrdered int, w int) r1cs.R1C {
	var t0, t1, t2, t3 big.Int

	// L
	L := r1cs.LinearExpression{
		cs.term(cs.Wires[win.b0].WireIDOrdering, *bOne),
	}

	t0.Neg(&win.lookuptable[0]).
		Add(&t0, &win.lookuptable[1])
	t1.Sub(&win.lookuptable[0], &win.lookuptable[1]).
		Sub(&t1, &win.lookuptable[2]).
		Add(&t1, &win.lookuptable[3])
	// R
	R := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, t0),
		cs.term(cs.Wires[win.b1].WireIDOrdering, t1),
	}

	t2.Neg(&win.lookuptable[0])
	t3.Set(&win.lookuptable[0])
	t3.Sub(&t3, &win.lookuptable[2])
	// O
	O := r1cs.LinearExpression{
		cs.term(oneWireIDOrdered, t2),
		cs.term(cs.Wires[win.b1].WireIDOrdering, t3),
		cs.term(cs.Wires[w].WireIDOrdering, *bOne),
	}

	return r1cs.R1C{L: L, R: R, O: O, Solver: backend.SingleOutput}
}

// func (win *lutExpression) string() string {

// 	var lookuptablereg [4]big.Int
// 	for i := 0; i < 4; i++ {
// 		lookuptablereg[i] = win.lookuptable[i] //.ToRegular()
// 	}

// 	res := "(" + win.b0.String() + ")*("
// 	res = res + "-" + lookuptablereg[0].String()
// 	res = res + "+" + lookuptablereg[0].String() + "*" + win.b1.String() + "+" + lookuptablereg[1].String()
// 	res = res + "-" + lookuptablereg[1].String() + "*" + win.b1.String()
// 	res = res + "-" + lookuptablereg[2].String() + "*" + win.b1.String()
// 	res = res + "+" + lookuptablereg[3].String() + "*" + win.b1.String() + ")="
// 	res = res + lookuptablereg[0].String() + "-" + lookuptablereg[0].String() + "*" + win.b1.String()
// 	res = res + "+" + lookuptablereg[2].String() + "*" + win.b1.String()
// 	return res
// }