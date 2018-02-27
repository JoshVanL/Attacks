package main

import (
	"fmt"
	"crypto/sha1"
	"os"

	"./oaep_c"
	"./utils"
)

var (
	c *oaep_c.Conf
)

func main() {
	var err os.Error

	c, err = oaep_c.NewConf("oaep/23305.conf")
	if err != nil {
		panic(err)
	}

	i2osp_test(1, 4, []byte{0, 0, 0, 1})
	i2osp_test(2, 4, []byte{0, 0, 0, 2})
	i2osp_test(3, 4, []byte{0, 0, 0, 3})
	i2osp_test(4, 4, []byte{0, 0, 0, 4})

	hex2oct_test([]byte{'0'}, []byte{0})
	hex2oct_test([]byte{'0', '0'}, []byte{0})
	hex2oct_test([]byte{'0', '0', '0'}, []byte{0, 0})
	hex2oct_test([]byte{'0', '1', '0'}, []byte{0, 16})
	hex2oct_test([]byte{'0', '1', '1'}, []byte{0, 17})
	hex2oct_test([]byte{'9', '0', '9'}, []byte{9, 9})
	hex2oct_test([]byte{'9', 'F', 'F'}, []byte{9, 255})

	xor_test([]byte{0}, []byte{0}, []byte{0})
	xor_test([]byte{0}, []byte{1}, []byte{1})
	xor_test([]byte{1}, []byte{1}, []byte{0})
	xor_test([]byte{2}, []byte{1}, []byte{3})
	xor_test([]byte{1, 2}, []byte{1}, []byte{1, 3})
	xor_test([]byte{1, 2}, []byte{1}, []byte{1, 3})
	xor_test([]byte{0, 1, 2}, []byte{1}, []byte{0, 1, 3})
	xor_test([]byte{5, 1, 2}, []byte{1, 0, 1}, []byte{4, 1, 3})

	hash_test()

	append_test([]byte{1, 0, 0}, []byte{5, 5, 5, 6}, []byte{1, 0, 0, 5, 5, 5, 6})

	hash := sha1.New()
	hash.Write([]byte{0})
	fmt.Printf("%v\n", hash.Sum())
}

func hex2oct_test(hex, exp []byte) {
	got := utils.HexToOct(hex)
	expBytes(exp, got)
}

func expBytes(exp, got []byte) {
	if len(exp) != len(got) {
		fmt.Printf("FAILED. exp=%v got=%v\n", exp, got)
		return

	}
	for i := range exp {
		if exp[i] != got[i] {
			fmt.Printf("FAILED. exp=%v got=%v\n", exp, got)
			return
		}
	}
	fmt.Printf("PASSED.\n")
}

func expInt(exp, got int) {
	if exp != got {
		fmt.Printf("FAILED. exp=%d got=%d\n", exp, got)
		return
	}

	fmt.Printf("PASSED.\n")
}
