package main

import (
	"fmt"
	//"os"
	"big"

	"./montgomery"
	//"./utils"
)

var (
	c *montgomery.Montgomery
)

type Test struct {
	x, y, m, answer *big.Int
}

func main() {

	m := big.NewInt(187)
	T := big.NewInt(563)

	answer := big.NewInt(19)
	result := montgomery.Reduction(m, T)

	if answer.Cmp(result) != 0 {
		fmt.Printf("montgomery reduction test failed\n")
	}

	tests := make([]Test, 5)

	//tests = []Test{
	tests[0] = Test{big.NewInt(70), big.NewInt(91), big.NewInt(563), big.NewInt(177)}
	tests[1] = Test{big.NewInt(91), big.NewInt(70), big.NewInt(563), big.NewInt(177)}
	tests[2] = Test{big.NewInt(456), big.NewInt(123), big.NewInt(789), big.NewInt(69)}
	tests[3] = Test{big.NewInt(123), big.NewInt(456), big.NewInt(789), big.NewInt(69)}
	tests[4] = Test{big.NewInt(1234567), big.NewInt(890123), big.NewInt(999999999), big.NewInt(916482839)}
	//}

	for i, a := range tests {
		result, _ := montgomery.MontgomeryMul(a.x, a.y, a.m)

		if a.answer.Cmp(result) != 0 {
			fmt.Printf("montgomery multiplication test failed\n")
			fmt.Printf("(%v) %v != %v\n", i, a.answer, result)
			return
		}
	}

	test2 := make([]Test, 3)

	test2[0] = Test{big.NewInt(7), big.NewInt(10), big.NewInt(13), big.NewInt(4)}
	test2[1] = Test{big.NewInt(2), big.NewInt(8), big.NewInt(9), big.NewInt(4)}
	test2[2] = Test{big.NewInt(2), big.NewInt(54), big.NewInt(17), big.NewInt(13)}

	for i, a := range test2 {
		result, err := montgomery.MontgomeryExp(a.x, a.y, a.m)

		if err == -1 {
			fmt.Printf("x or y was not reduced prior to exponentiation\n")
			return
		}
		if test2[i].answer.Cmp(result) != 0 {
			fmt.Printf("montgomery exp test failed\n")
			fmt.Printf("(%v) %v != %v\n", i, a.answer, result)
			return
		}
	}
	//var err os.Error

	//c, err = oaep_c.NewConf("oaep/23305.conf")
	//if err != nil {
	//	panic(err)
	//}

	//i2osp_test(1, 4, []byte{0, 0, 0, 1})
	//i2osp_test(2, 4, []byte{0, 0, 0, 2})
	//i2osp_test(3, 4, []byte{0, 0, 0, 3})
	//i2osp_test(4, 4, []byte{0, 0, 0, 4})

	//hex2oct_test([]byte{'0'}, []byte{0})
	//hex2oct_test([]byte{'0', '0'}, []byte{0})
	//hex2oct_test([]byte{'0', '0', '0'}, []byte{0, 0})
	//hex2oct_test([]byte{'0', '1', '0'}, []byte{0, 16})
	//hex2oct_test([]byte{'0', '1', '1'}, []byte{0, 17})
	//hex2oct_test([]byte{'9', '0', '9'}, []byte{9, 9})
	//hex2oct_test([]byte{'9', 'F', 'F'}, []byte{9, 255})

	//xor_test([]byte{0}, []byte{0}, []byte{0})
	//xor_test([]byte{0}, []byte{1}, []byte{1})
	//xor_test([]byte{1}, []byte{1}, []byte{0})
	//xor_test([]byte{2}, []byte{1}, []byte{3})
	//xor_test([]byte{1, 2}, []byte{1}, []byte{1, 3})
	//xor_test([]byte{1, 2}, []byte{1}, []byte{1, 3})
	//xor_test([]byte{0, 1, 2}, []byte{1}, []byte{0, 1, 3})
	//xor_test([]byte{5, 1, 2}, []byte{1, 0, 1}, []byte{4, 1, 3})

	//hash_test()

	//append_test([]byte{1, 0, 0}, []byte{5, 5, 5, 6}, []byte{1, 0, 0, 5, 5, 5, 6})

	//hash := sha1.New()
	//hash.Write([]byte{0})
	//fmt.Printf("%v\n", hash.Sum())
}

//func hex2oct_test(hex, exp []byte) {
//	got := utils.HexToOct(hex)
//	expBytes(exp, got)
//}
//
//func expBytes(exp, got []byte) {
//	if len(exp) != len(got) {
//		fmt.Printf("FAILED. exp=%v got=%v\n", exp, got)
//		return
//
//	}
//	for i := range exp {
//		if exp[i] != got[i] {
//			fmt.Printf("FAILED. exp=%v got=%v\n", exp, got)
//			return
//		}
//	}
//	fmt.Printf("PASSED.\n")
//}
//
//func expInt(exp, got int) {
//	if exp != got {
//		fmt.Printf("FAILED. exp=%d got=%d\n", exp, got)
//		return
//	}
//
//	fmt.Printf("PASSED.\n")
//}
