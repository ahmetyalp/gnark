package compress

import (
	"errors"
	"github.com/consensys/compress/lzss"
	realHash "hash"
	"math/big"

	"github.com/consensys/compress"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
)

// Checksum packs the words into as few field elements as possible, and returns the hash of the packed words
func Checksum(api frontend.API, words []frontend.Variable, nbWords frontend.Variable, wordLen int) frontend.Variable {
	packed := pack(api, words, wordLen)
	hsh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hsh.Write(packed...)
	hsh.Write(nbWords)
	return hsh.Sum()
}

func pack(api frontend.API, words []frontend.Variable, wordLen int) []frontend.Variable {
	wordsPerElem := (api.Compiler().FieldBitLen() - 1) / wordLen
	packed := make([]frontend.Variable, (len(words)+wordsPerElem-1)/wordsPerElem)
	radix := 1 << wordLen
	for i := range packed {
		packed[i] = 0
		for j := wordsPerElem - 1; j >= 0; j-- {
			absJ := i*wordsPerElem + j
			if absJ >= len(words) {
				continue
			}
			packed[i] = api.Add(words[absJ], api.Mul(packed[i], radix))
		}
	}
	return packed
}

type NumReader struct {
	api       frontend.API
	c         []frontend.Variable
	stepCoeff int
	maxCoeff  int
	nbWords   int
	nxt       frontend.Variable
}

func NewNumReader(api frontend.API, c []frontend.Variable, numNbBits, wordNbBits int) *NumReader {
	nbWords := numNbBits / wordNbBits
	stepCoeff := 1 << wordNbBits
	nxt := ReadNum(api, c, nbWords, stepCoeff)
	return &NumReader{
		api:       api,
		c:         c,
		stepCoeff: stepCoeff,
		maxCoeff:  1 << numNbBits,
		nxt:       nxt,
		nbWords:   nbWords,
	}
}

func ReadNum(api frontend.API, c []frontend.Variable, nbWords, stepCoeff int) frontend.Variable {
	res := frontend.Variable(0)
	for i := 0; i < nbWords && i < len(c); i++ {
		res = api.Add(c[i], api.Mul(res, stepCoeff))
	}
	return res
}

// Next returns the next number in the sequence. assumes bits past the end of the slice are 0
func (nr *NumReader) Next() frontend.Variable {
	res := nr.nxt

	if len(nr.c) != 0 {
		nr.nxt = nr.api.Sub(nr.api.Mul(nr.nxt, nr.stepCoeff), nr.api.Mul(nr.c[0], nr.maxCoeff))

		if nr.nbWords < len(nr.c) {
			nr.nxt = nr.api.Add(nr.nxt, nr.c[nr.nbWords])
		}

		nr.c = nr.c[1:]
	}

	return res
}

// ToSnarkData breaks a stream up into words of the right size for snark consumption, and computes the checksum of that data in a way congruent with Checksum
func ToSnarkData(curveId ecc.ID, s compress.Stream, paddedNbBits int, level lzss.Level) (words []frontend.Variable, checksum []byte, err error) {

	wordNbBits := int(level)

	paddedNbWords := paddedNbBits / wordNbBits

	if paddedNbWords*wordNbBits != paddedNbBits {
		return nil, nil, errors.New("the padded size must divide the word length")
	}

	wStream := s.BreakUp(1 << wordNbBits)
	wPadded := wStream

	if contentNbBits := wStream.Len() * wordNbBits; contentNbBits != paddedNbBits {
		wPadded.D = make([]int, paddedNbWords)
		copy(wPadded.D, wStream.D)
	}

	words = test_vector_utils.ToVariableSlice(wPadded.D)

	var hsh realHash.Hash
	switch curveId {
	case ecc.BLS12_377:
		hsh = hash.MIMC_BLS12_377.New()
	case ecc.BN254:
		hsh = hash.MIMC_BN254.New()
	default:
		return nil, nil, errors.New("TODO Add switch-case for curve")
	}

	fieldNbBits := curveId.ScalarField().BitLen()
	fieldNbBytes := (fieldNbBits + 7) / 8
	packed := wPadded.Pack(fieldNbBits)
	byts := make([]byte, fieldNbBytes)

	for _, w := range packed {
		w.FillBytes(byts)
		hsh.Write(byts)
	}

	big.NewInt(int64(wStream.Len())).FillBytes(byts)
	hsh.Write(byts)

	checksum = hsh.Sum(nil)

	return
}