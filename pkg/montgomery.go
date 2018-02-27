package montgomery

import (
	"big"
	"encoding/binary"
	"fmt"
)

const (
	BYTES_PER_LIMB = 8
	LIMB_SIZE      = 64
)

type Montgomery struct {
	n   *big.Int
	o   uint64
	ro2 *big.Int
}

func NewMontgomery(N *big.Int) *Montgomery {
	return &Montgomery{
		n: N,
		ro2: Ro2(N),
		o: Omega(N),
	}
}

func Omega(N *big.Int) uint64 {
	o := big.NewInt(1)
	//n := getLimb(N, 0)

	for i := 1; i < LIMB_SIZE; i++ {
		//o *= o * n
		tmp := new(big.Int).Mul(o, N)
		o.Mul(o, tmp)
		o = o.SetBytes(o.Bytes()[0:BYTES_PER_LIMB])
	}

	return -getLimb(o, 0)
}

func Ro2(N *big.Int) *big.Int {
	//	ro2 := big.NewInt(1)
	//
	//	for i := 1; i < ceilDiv(len(N.Bytes()), BYTES_PER_LIMB)*LIMB_SIZE*2; i++ {
	//		ro2.Add(ro2, ro2)
	//
	//		if ro2.Cmp(N) > 0 {
	//			ro2.Sub(ro2, N)
	//		}
	//	}
	//	fmt.Printf(">>%s\n", ro2)
	//
	//b := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
	//i := int64(1)

	//for new(big.Int).Exp(b, big.NewInt(i), nil).Cmp(N) < 0 {
	//	i++
	//}

	//ro :=
	t := :

	return b
}

func (m *Montgomery) Red(z *big.Int) *big.Int {
	r := new(big.Int).Set(z)
	uiN := new(big.Int)

	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
		ui := getLimb(m.n, 0) * m.o
		uii := uToInt(ui)

		uiN.Mul(m.n, uii)
		r.Add(r, uiN)

		r.Rsh(r, BYTES_PER_LIMB)
	}

	if r.Cmp(m.n) >= 0 {
		r.Sub(r, m.n)
	}

	return r
}

func (m *Montgomery) Mul(x, y *big.Int) *big.Int {
	r := big.NewInt(0)

	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
		ui := (getLimb(r, 0) + (getLimb(y, i) * getLimb(x, 0))) * m.o
		//fmt.Printf(">>%v\n", getLimb(x, 0))
		//fmt.Printf(">>%v\n", getLimb(x, 0))

		yix := new(big.Int).Mul(x, uToInt(getLimb(y, i)))
		uiN := new(big.Int).Mul(m.n, uToInt(ui))

		r.Add(r, yix)
		r.Add(r, uiN)

		r.Rsh(r, 8)
	}

	if r.Cmp(m.n) >= 0 {
		r.Sub(r, m.n)
	}

	return r
}

func (m *Montgomery) Exp(x, y *big.Int) *big.Int {
	t_hat := m.Mul(big.NewInt(1), m.ro2)
	fmt.Printf(">%s\n", t_hat)
	x_hat := m.Mul(x, m.ro2)

	for i := 0; i < ceilDiv(len(y.Bytes()), BYTES_PER_LIMB); i++ {
		t_hat.Mul(t_hat, t_hat)

		if getLimb(y, i) > 0 {
			t_hat.Mul(y, x_hat)
		}
	}

	return t_hat.Mul(t_hat, big.NewInt(1))
}

func getLimb(z *big.Int, s int) uint64 {
	//if s >= ceilDiv(len(z.Bytes()), BYTES_PER_LIMB) {
	//	return 0
	//}
	b := z.Bytes()
	if s > len(b) {
		return 0
	}
	//fmt.Printf("%v\n", b)

	if len(b) < BYTES_PER_LIMB {
		tmp := make([]byte, BYTES_PER_LIMB)
		copy(tmp[BYTES_PER_LIMB-len(b):BYTES_PER_LIMB], b)
		b = tmp
	}
	//fmt.Printf("%v\n", b)

	//fmt.Printf("s:%d\n", s)
	//fmt.Printf("z:%s\n", z.String())

	return binary.BigEndian.Uint64(b[s : s+BYTES_PER_LIMB])
}

func uToInt(u uint64) *big.Int {
	b := make([]byte, BYTES_PER_LIMB)
	binary.BigEndian.PutUint64(b, u)

	return new(big.Int).SetBytes(b)
}

func ceilDiv(x, y int) int {
	r := x / y
	if x%y > 0 {
		r++
	}

	return r
}
