package utils

import (
	"fmt"
	"big"
	"os"
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
	if len(os.Args) < 2 || len(os.Args) > 3 {
		return nil, NewError(fmt.Sprintf("expected 1 or 2 argmuents, got=%d", len(os.Args)-1))
	}

	return os.Args[1:], nil
}

func IntToHex(z *big.Int) string {
	var str string

	num := new(big.Int)
	num.Set(z)

	power := new(big.Int)
	quot := new(big.Int)
	hex := big.NewInt(16)
	one := big.NewInt(1)
	index := big.NewInt(int64(z.Len() - 1))

	for num.Cmp(one) > 0 {
		power.Exp(hex, index, nil)

		if z.Cmp(power) < 0 {
			str = fmt.Sprintf("0%s", str)

		} else {
			quot, num = num.Div(num, power)
			str = fmt.Sprintf("%s%s", str, zToHex(quot))
		}

		index.Sub(index, big.NewInt(1))
	}

	return TrimLeft(str, '0')
}

func IntToHexBytes(z *big.Int) []byte {
	bytes := make([]byte, 2048)

	num := new(big.Int)
	num.Set(z)

	power := new(big.Int)
	quot := new(big.Int)
	hex := big.NewInt(16)
	one := big.NewInt(1)
	index := big.NewInt(int64(z.Len() - 1))

	loc := 0

	for num.Cmp(one) > 0 {
		power.Exp(hex, index, nil)

		if z.Cmp(power) < 0 {
			bytes[loc] = '0'

		} else {
			quot, num = num.Div(num, power)
			bytes[loc] = zToHexByte(quot)
		}

		index.Sub(index, big.NewInt(1))
		loc++
	}

	bytes[loc] = '\n'

	return TrimLeftBytes(bytes, 0)
}

func zToHex(z *big.Int) string {
	var b byte

	if len(z.Bytes()) > 0 {
		b = z.Bytes()[0]
	}

	if b > 9 {
		return fmt.Sprintf("%s", string('A'+(b-10)))
	}

	return fmt.Sprintf("%s", string(b+'0'))
}

func zToHexByte(z *big.Int) byte {
	var b byte

	if len(z.Bytes()) > 0 {
		b = z.Bytes()[0]
	}

	if b > 9 {
		return 'A' + (b - 10)
	}

	return b + '0'
}

func TrimLeft(str string, b byte) string {
	i := 0

	for str[i] == b {
		i++
	}

	return str[i:]
}

func TrimLeftBytes(bytes []byte, b byte) []byte {
	s, e := 0, len(bytes)-1

	for bytes[s] == 48 {
		s++
	}

	for bytes[e] == 0 {
		e--
	}

	a := make([]byte, e-s+1)
	copy(a, bytes[s:e+5])

	return a
}
