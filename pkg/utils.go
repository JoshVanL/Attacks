package utils

import (
	"fmt"
	"big"
	"os"
)

const (
	WORD_LENGTH = 256
	BASE        = 16
)

func NewError(err string) os.Error { return os.NewError(err) }

func Error(str string, err os.Error) os.Error {
	return os.NewError(fmt.Sprintf("%s: %v", str, err))
}

func Fatal(err os.Error) {
	fmt.Printf("%v\n", err)
	os.Exit(1)
}

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

func AppendBytes(slice [][]byte, elem []byte) [][]byte {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elem
		return slice
	}

	fresh := make([][]byte, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elem
	return fresh
}

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

func IntToHex(z *big.Int) []byte {
	bytes := make([]byte, 512)

	num := new(big.Int)
	num.Set(z)

	power := new(big.Int)
	quot := new(big.Int)
	hex := big.NewInt(BASE)
	one := big.NewInt(1)
	zero := big.NewInt(0)
	index := big.NewInt(WORD_LENGTH)

	loc := 0

	for index.Cmp(zero) >= 0 {
		power.Exp(hex, index, nil)

		if z.Cmp(power) < 0 {
			bytes[loc] = '0'

		} else {
			quot, num = num.Div(num, power)
			bytes[loc] = zToHex(quot)
		}

		index.Sub(index, one)
		loc++
	}

	bytes[loc] = '\n'

	return TrimLeft(bytes)
}

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

func zToHex(z *big.Int) byte {
	var b byte

	if len(z.Bytes()) > 0 {
		b = z.Bytes()[0]
	}

	if b > 9 {
		return 'A' + (b - 10)
	}

	return b + '0'
}

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

func CeilingDiv(x *big.Int, y *big.Int) *big.Int {
	z := new(big.Int)
	z, r := z.Div(x, y)

	if r.Cmp(big.NewInt(0)) > 0 {
		z.Add(z, big.NewInt(1))
	}

	return z
}
