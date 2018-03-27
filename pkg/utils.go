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

// Convert big.Int to hex byte representation
func ZToHex(z *big.Int) byte {
	var b byte

	if len(z.Bytes()) > 0 {
		b = z.Bytes()[0]
	}

	if b > 9 {
		return 'A' + (b - 10)
	}

	return b + '0'
}

// Convert Hex Bytes (as string) to Octet bytes
func HexToBytes(hex []byte) []byte {
	b := make([]byte, len(hex))

	for i := range hex {
		b[i] = hexByteToByte(hex[i])
	}

	return b
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

// Ceiling division on big.Int
func CeilingDiv(x *big.Int, y *big.Int) *big.Int {
	z := new(big.Int)
	z, r := z.Div(x, y)

	if r.Cmp(big.NewInt(0)) > 0 {
		z.Add(z, big.NewInt(1))
	}

	return z
}

// Split byte slice by parameter s
func SplitBytes(b []byte, s byte) ([]byte, []byte) {
	i := 0

	for b[i] != s {
		i++
		if i == len(b) {
			return b, nil
		}
	}

	return b[0:i], b[i+1 : len(b)]
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

// Find a byte s starting from 'start' in a byte slice
// Return the index and byte slice split
func Find(x []byte, s byte, start int) (index int, split []byte) {
	for i, b := range x {
		if i >= start && b == s {
			return i, x[s:len(x)]
		}
	}

	return -1, nil
}

// Convert hex string byte to number at byte
func hexByteToByte(b byte) byte {
	if b >= 'A' {
		return b - 55
	}

	return b - 48
}

// Convert hexadecimal byte string to Octet byte slice
func HexToOct(hex []byte) []byte {
	var b []byte
	if len(hex)%2 == 0 {
		b = make([]byte, len(hex)/2)
		for i := 0; i < len(b); i++ {
			b[i] = hexByteToByte(hex[2*i]) * 16
			b[i] += hexByteToByte(hex[2*i+1])
		}
	} else {
		b = make([]byte, (len(hex)+1)/2)
		b[0] = hexByteToByte(hex[0])
		for i := 1; i < len(b); i++ {
			b[i] = hexByteToByte(hex[(2*i)-1]) * 16
			b[i] += hexByteToByte(hex[2*i])
		}
	}

	return b
}

// Generate a random big.Int of byte length x**e
func RandInt(x, e int64) *big.Int {
	n := new(big.Int).Exp(big.NewInt(x), big.NewInt(e), nil)
	b := make([]byte, len(n.Bytes()))
	for i := range b {
		b[i] = byte(rand.Intn(255))
	}

	z := new(big.Int).SetBytes(b)
	z.Mod(z, n)

	return z
}

// Return big.Int as the sum of byte slices
func SumBytes(bytes [][]byte) (*big.Int, os.Error) {
	z := new(big.Int)
	for i := range bytes {
		n := new(big.Int)
		_, ok := n.SetString(string(bytes[i]), 10)
		if !ok {
			return nil, os.NewError("failed to convert conf value to hex string")
		}

		z.Add(z, n)
	}

	return z, nil
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

// Convert a binary string into a big.Int
func BinaryStringToInt(str string) *big.Int {
	z := big.NewInt(0)
	pow := big.NewInt(1)
	two := big.NewInt(2)

	for i := len(str) - 1; i >= 0; i-- {
		s := big.NewInt(int64(str[i] - 48))
		s.Mul(s, pow)
		z.Add(z, s)

		pow.Mul(pow, two)
	}

	return z
}

// Calculate the average float from a slice of floats
func AverageFloat(zs []float64) float64 {
	if len(zs) == 0 {
		return 0
	}

	z := float64(0)
	for _, n := range zs {
		z += n
	}

	return z / float64(len(zs))
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

func Contains(xs []int, x int) bool {
	for _, i := range xs {
		if x == i {
			return true
		}
	}

	return false
}

func XORToInt(a byte, b int) int { return int(a ^ byte(b)) }

// Wait group is a method of synchronisation of go routines
func NewWaitGroup(n int) *WaitGroup {
	return &WaitGroup{
		n: n,
		stopCh: make(chan struct{}),
	}
}

func (w *WaitGroup) Done() {
	w.n--
	if w.n == 0 {
		close(w.stopCh)
	}
}

func (w *WaitGroup) Wait() { <-w.stopCh }


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

func AppendBytesSlices(slice [][]byte, elems []byte) [][]byte {
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

func AppendBigInt(slice []*big.Int, elem *big.Int) []*big.Int {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elem
		return slice
	}

	fresh := make([]*big.Int, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elem
	return fresh
}
