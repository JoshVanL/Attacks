package oaep

import (
	"big"
	"fmt"
)

type Conf struct {
	n      int
	values [4]*big.Int
	fields [4]string
	bytes  [4][]byte
}

func Foo() {
	fmt.Printf("hello there!\n")
}
