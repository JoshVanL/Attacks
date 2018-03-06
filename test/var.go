package main

import (
	"fmt"
	"math"
	"big"
	"encoding/binary"
)

func main() {
	T := []float64{12, 14, 8, 12, 15, 10}
	M := []float64{1, 1, 0, 1, 1, 0}

	EM := AverageFloat(M)
	fmt.Printf("EM: %v\n", EM)
	MEM := make([]float64, len(M))
	for i := range M {
		MEM[i] = M[i] - EM
	}

	ET := AverageFloat(T)
	fmt.Printf("ET: %v\n", ET)
	TET := make([]float64, len(T))
	for i := range T {
		TET[i] = T[i] - ET
	}

	var R float64
	for i := range T {
		R += MEM[i] * TET[i]
	}

	R = R / float64(len(T))

	//R := AverageFloat(MEM) * AverageFloat(TET)
	fmt.Printf("MEM: %v\n", AverageFloat(MEM))
	fmt.Printf("TET: %v\n", AverageFloat(TET))
	fmt.Printf("R: %v\n", R)

	VM := make([]float64, len(M))
	for i := range M {
		VM[i] = math.Pow(M[i]-EM, 2)
	}
	varM := AverageFloat(VM)

	VT := make([]float64, len(T))
	for i := range T {
		VT[i] = math.Pow(T[i]-ET, 2)
	}
	varT := AverageFloat(VT)

	varMT := math.Sqrt(varM * varT)

	R = R / varMT

	fmt.Printf("R: %v\n", R)

	n := big.NewInt(1234).Bytes()
	fmt.Printf("n :%v\n", n)
	if len(n) < 8 {
		tmp := make([]byte, 8)
		copy(tmp[8-len(n):8], n)
		n = tmp
	}
	fmt.Printf("n :%v\n", n)
	f := float64(binary.BigEndian.Uint64(n))
	fmt.Printf("%v\n", f)

	//cpyM := make([]float64, len(M))
	//copy(cpyM, M)

	//eM := AverageFloat(M)
	//for i := range cpyM {
	//	cpyM[i] = cpyM[i] - eM
	//}
	//eeM := AverageFloat(cpyM)

	//cpyT := make([]float64, len(T))
	//copy(cpyT, T)
	//eT := AverageFloat(T)
	//for i := range cpyT {
	//	cpyT[i] = cpyT[i] - eT
	//}
	//eeT := AverageFloat(cpyT)

	//// var(X)  = E(X^2) - E(X)^2
	//eT2 := math.Pow(eT, 2)
	//copy(cpyT, T)
	//for i := range cpyT {
	//	cpyT[i] = math.Pow(cpyT[i], 2)
	//}
	//e2T := AverageFloat(cpyT)
	//varT := e2T - eT2

	//eM2 := math.Pow(eM, 2)
	//copy(cpyM, M)
	//for i := range cpyM {
	//	cpyM[i] = math.Pow(cpyM[i], 2)
	//}
	//e2M := AverageFloat(cpyM)
	//varM := e2M - eM2

	//varM = varT * varM
	//varM = math.Sqrt(varM)
	//eeM = eeM * eeT
	//eeM = eeM / varM
	//fmt.Printf("%v\n", eeM)

	fmt.Printf("====")
}


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
