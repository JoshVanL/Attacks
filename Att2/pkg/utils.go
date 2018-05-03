///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package utils

import (
	"fmt"
	"big"
	"rand"
	"os"
	"encoding/binary"
	"time"
)

const (
	WORD_LENGTH = 256
	BASE        = 16
)

type WaitGroup struct {
	n      int
	stopCh chan struct{}
}

// Generic error wrapper functions. Go has a built in error primitive type but
// since this is such an old version, it doesn't have it yet!
func NewError(err string) os.Error { return os.NewError(err) }

func Error(str string, err os.Error) os.Error {
	return os.NewError(fmt.Sprintf("%s: %v", str, err))
}

func Fatal(err os.Error) {
	fmt.Printf("%v\n", err)
	os.Exit(1)
}

// Function for checking CLI arguments
func ParseArguments() ([]string, os.Error) {
	var args []string

	if len(os.Args) < 2 || len(os.Args) > 3 {
		return nil, NewError(fmt.Sprintf("expected 1 or 2 argmuents, got=%d", len(os.Args)-1))
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, Error("failed to get current working directory", err)
	}

	for i := 1; i < len(os.Args); i++ {
		args = Append(args, fmt.Sprintf("%s/%s", wd, os.Args[i]))
	}

	return args, nil
}

// Pad a byte slice with 0's from the s bit position
func Pad(bytes []byte, s int) []byte {
	s++
	b := make([]byte, s)

	if s < len(bytes) {
		return bytes
	}

	for i := 0; i < s-len(bytes); i++ {
		b[i] = '0'
	}

	for i := 0; i < len(bytes); i++ {
		b[i+s-len(bytes)] = bytes[i]
	}

	return b
}

func HammingWeight(v byte) byte {
	v = (v & 0x55) + ((v >> 1) & 0x55)
	v = (v & 0x33) + ((v >> 2) & 0x33)
	return (v + (v >> 4)) & 0xF
}

// Trim byte slice left of white space
func TrimLeft(bytes []byte) []byte {
	s, e := 0, len(bytes)-1

	for bytes[s] == 48 || bytes[s] == 0 {
		s++
	}
	for bytes[e] == 0 {
		e--
	}

	return bytes[s : e+1]
}

// Calculate XOR on two byte slices
func XOR(x []byte, y []byte) []byte {
	var cpy int
	var size int

	var xstart int
	var ystart int

	var z []byte

	if len(x) > len(y) {
		size = len(x)
		cpy = len(x) - len(y)
		ystart = cpy
		z = make([]byte, size)
		for i := 0; i < cpy; i++ {
			z[i] = x[i]
		}
	} else {
		size = len(y)
		cpy = len(y) - len(x)
		xstart = cpy
		z = make([]byte, size)
		for i := 0; i < cpy; i++ {
			z[i] = y[i]
		}
	}

	for i := cpy; i < size; i++ {
		z[i] = x[i-xstart] ^ y[i-ystart]
	}

	return z
}

// Convert hex string byte to number at byte
func hexByteToByte(b byte) byte {
	if b >= 'A' {
		return b - 55
	}

	return b - 48
}

// Generate a random big.Int of byte length x**e
func RandInt(x, e int64) *big.Int {
	rnd := rand.New(rand.NewSource(time.Nanoseconds()))
	n := new(big.Int).Exp(big.NewInt(x), big.NewInt(e), nil)
	b := make([]byte, len(n.Bytes()))
	for i := range b {
		b[i] = byte(rnd.Intn(255))
	}

	z := new(big.Int).SetBytes(b)
	z.Mod(z, n)

	return z
}

// Calculate byte slice to big.Int
func BytesToInt(b []byte) (*big.Int, os.Error) {
	b = b[0 : len(b)-1]

	z := new(big.Int)
	_, ok := z.SetString(string(b), BASE)
	if !ok {
		return nil, os.NewError("failed to convert conf value to hex string")
	}

	return z, nil
}

// Convert big.Int to float64
func BigIntToFloat(z *big.Int) float64 {
	b := z.Bytes()
	if len(b) < 8 {
		tmp := make([]byte, 8)
		copy(tmp[8-len(b):8], b)
		b = tmp
	}

	return float64(binary.BigEndian.Uint64(b))
}

func Transpose(m [][]float64) [][]float64 {
	r := make([][]float64, len(m[0]))
	for x, _ := range r {
		r[x] = make([]float64, len(m))
	}
	for y, s := range m {
		for x, e := range s {
			r[x][y] = e
		}
	}
	return r
}


// Go has a built in function append which will append arbitrary slices
// together.  Since this is a very old version, it doesn't even have that!
// These functions will append a selection of slice types.
func Append(slice []string, elem string) []string {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elem
		return slice
	}

	fresh := make([]string, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elem
	return fresh
}

func AppendByte(slice []byte, elem byte) []byte {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elem
		return slice
	}

	fresh := make([]byte, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elem
	return fresh
}

func AppendFloat(slice []float64, elem float64) []float64 {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elem
		return slice
	}

	fresh := make([]float64, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elem
	return fresh
}


func AppendByteSlice(slice []byte, elems []byte) []byte {
	fresh := make([]byte, len(slice))
	copy(fresh, slice)

	for _, elem := range elems {
		fresh = AppendByte(fresh, elem)
	}

	return fresh
}

func AppendByte2(slice [][]byte, elems []byte) [][]byte {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elems
		return slice
	}

	fresh := make([][]byte, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elems
	return fresh
}
