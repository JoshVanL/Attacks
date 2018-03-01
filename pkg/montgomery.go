package montgomery

import (
	"big"
	"encoding/binary"
	"fmt"
	//"os"
)

const (
	BYTES_PER_LIMB = 8
	LIMB_SIZE      = 64
	MaxUint64      = ^uint64(0)
)

type Montgomery struct {
	n   *big.Int
	o   *big.Int
	ro  *big.Int
	ro2 *big.Int
}

func NewMontgomery(N *big.Int) *Montgomery {
	R, R2 := Ro(N)
	return &Montgomery{
		n: N,
		ro: R,
		ro2: R2,
		o: Omega(N, R),
	}
}

func Omega(N, R *big.Int) *big.Int {
	nm := new(big.Int).Neg(N)
	//if nm.Cmp(big.NewInt(0)) < 0 {
	//	nm.Add(nm, R)
	//}
	nm = nm.Mod(nm, R)
	o := ModInverse(nm, R)

	//o := big.NewInt(1)
	//for i := 1; i < 64; i++ {
	//	o.Mul(o, getLimb(N, 0))
	//	o = getLimb(o, 0)
	//}
	////fmt.Printf("o %s\n", o)
	////fmt.Printf("o %s\n", getLimb(o, 0))

	//return getLimb(o, 0)
	return o
}

func Ro(N *big.Int) (R *big.Int, R2 *big.Int) {
	b := big.NewInt(2)
	n := N.Len()
	R = new(big.Int).Exp(b, big.NewInt(int64(n)), nil)
	R2 = new(big.Int).Exp(R, b, N)

	return R, R2
}

func (m *Montgomery) Reduction(t *big.Int) *big.Int {

	//b := big.NewInt(2)
	//n := m.Len()

	//R := new(big.Int).Exp(b, big.NewInt(int64(n)), nil)

	//nm := new(big.Int).Neg(m)
	//if nm.Cmp(big.NewInt(0)) < 0 {
	//	nm.Add(nm, R)
	//}
	//nm = nm.Mod(nm, R)
	//mp := ModInverse(nm, R)

	//A := new(big.Int).Set(t)

	//ui := mp.Mod(mp, b)
	//ui = ui.Mul(ui, m)
	//bi := new(big.Int)
	//for i := 0; i < n; i++ {
	//	ai := bit(A, i)
	//	if ai == 1 {
	//		bi = bi.Exp(b, big.NewInt(int64(i)), nil)
	//		ad := new(big.Int).Mul(ui, bi)
	//		A = A.Add(A, ad)
	//	}
	//}

	//r := new(big.Int).Rsh(A, n)
	//if cmp := r.Cmp(m); cmp == 0 || cmp == 1 {
	//	r = r.Sub(r, m)
	//}

	//return r

	r := new(big.Int).Set(t)
	for i := 0; i < ceilDiv(m.n.Len(), 64); i++ {
		ui := new(big.Int).Mul(getLimb(r, 0), m.o)
		ui.Mul(ui, m.n)
		r.Add(r, ui)

		a := new(big.Int).Rsh(r, 6)
		r = a
	}

	if r.Cmp(m.n) >= 0 {
		r.Sub(r, m.n)
	}

	return r
}

func ModInverse(g, n *big.Int) *big.Int {
	z := new(big.Int)

	if g.Cmp(big.NewInt(0)) < 0 {
		// GCD expects parameters a and b to be > 0.
		g2 := new(big.Int)
		g = g2.Mod(g, n)
	}
	d := new(big.Int)
	big.GcdInt(d, z, nil, g, n)
	// x and y are such that g*x + n*y = d. Since g and n are
	// relatively prime, d = 1. Taking that modulo n results in
	// g*x = 1, therefore x is the inverse element.
	if z.Cmp(big.NewInt(0)) < 0 {
		z.Add(z, n)
	}
	return z
}

func (m *Montgomery) montgomeryMul(x, y *big.Int) (*big.Int, int) {

	//if x.Cmp(m.n) == 1 || y.Cmp(m.n) == 1 {
	//	return x, -1
	//}

	//b := big.NewInt(64)
	b := big.NewInt(2)
	n := m.n.Len()

	A := big.NewInt(0)

	//ui := new(big.Int).Mod(m.o, b)
	//ui = ui.Mul(ui, m.n)

	y0 := big.NewInt(bit(y, 0))
	//y0 := getLimb(y, 0)
	//x0 := getLimb(x, 0)

	//for i := 0; i < ceilDiv(n, 64); i++ {
	for i := 0; i < n; i++ {

		a0 := big.NewInt(bit(A, 0))
		xi := big.NewInt(bit(x, i))
		ui := new(big.Int).Mul(xi, y0)
		ui.Add(ui, a0)
		ui.Mul(ui, m.o)
		ui.Mod(ui, b)
		ui.Mul(ui, m.n)

		ad := new(big.Int).Mul(xi, y)
		ad.Add(ad, ui)
		ad.Add(ad, A)
		a := new(big.Int).Rsh(ad, 1)
		A = a

		//fmt.Printf("\n")
		//fmt.Printf(">x %v\n", x.Bytes())
		//fmt.Printf(">xi %v\n", xi.Bytes())
		//fmt.Printf(">i %d\n", i)
		//a0 := getLimb(A, 0)
		//xi := getLimb(x, i)
		//ui := new(big.Int).Mul(xi, y0)
		//ui.Add(ui, a0)
		//ui.Mul(ui, m.o)
		//ui.Mod(ui, b)
		//ui.Mul(ui, m.n)

		//ad := new(big.Int).Mul(xi, y)
		//ad.Add(ad, ui)
		//ad.Add(ad, A)
		////if ad.Len() >= 64 {
		//a := new(big.Int).Rsh(ad, 6)
		//A = a
		//} else {
		//	A = big.NewInt(0)
		//}

		//ui := new(big.Int).Mul(getLimb(y, i), x0)
		//ui.Add(getLimb(A, 0), ui)
		//ui.Mul(ui, m.o)

		//yix := new(big.Int).Mul(x, getLimb(y, i))
		//uiN := new(big.Int).Mul(m.n, ui)

		//A.Add(A, yix)
		//A.Add(A, uiN)

		//a := new(big.Int).Rsh(A, 64)
		//A = a
	}

	extra := 0
	//The big bad "extra reduction" step :)
	if A.Cmp(m.n) >= 0 {
		A.Sub(A, m.n)
		extra = 1
	}

	//A = A.Mul(A, m.ro)
	//A = A.Mod(A, m.n)
	fmt.Printf("A %s\n", A)
	////fmt.Printf("")
	//os.Exit(1)

	return A, extra
}

func (m *Montgomery) MontgomeryExp(x, y *big.Int) (*big.Int, int) {
	if x.Cmp(m.n) == 1 {
		return x, -1
	}

	A := new(big.Int).Mod(m.ro, m.n)
	xs, _ := m.montgomeryMul(x, m.ro2)

	//fmt.Printf("HERE\n")
	//fmt.Printf("%d\n", e.Len())
	//extras tracks how many "extra reductions" where performed
	//over the course of the exponentiation.
	extras := 0
	extra := 0
	for i := y.Len(); i >= 0; i-- {
		A, extra = m.montgomeryMul(A, A)
		extras += extra
		if bit(y, i) == 1 {
			A, extra = m.montgomeryMul(A, xs)
			extras += extra
		}
		extra = 0
	}
	A, extra = m.montgomeryMul(A, big.NewInt(1))
	//fmt.Printf("HERE\n")

	extras += extra

	return A, extras

	//fmt.Printf("ro2 %s\n", m.ro2)
	//fmt.Printf("o %s\n", m.o)
	//fmt.Printf("N %s\n", m.n)
	//fmt.Printf("%s\n", m.n)
	////fmt.Printf("%s\n", m.y)
	////fmt.Printf("")

	//t_hat := big.NewInt(1)
	//x_hat, _ := m.montgomeryMul(t_hat, m.ro2)
	//x_hat, _ = m.montgomeryMul(x, m.ro2)

	//for i := ceilDiv(y.Len(), 64) - 1; i >= 0; i-- {
	//	t_hat, _ = m.montgomeryMul(t_hat, t_hat)
	//	if getLimb(y, i).Cmp(big.NewInt(0)) > 0 {
	//		t_hat, _ = m.montgomeryMul(t_hat, x_hat)
	//	}

	//}
	//r, _ := m.montgomeryMul(t_hat, big.NewInt(1))

	//return r, 0
}

func bit(x *big.Int, i int) int64 {
	b := x.Bytes()
	if len(b) == 0 {
		return 0
	}

	if len(b) < (i/8)+1 {
		return 0
	}

	n := int64(b[len(b)-1-(i/8)])
	return (n >> (uint(i % 8))) & 1
}

func word(x *big.Int, i int) *big.Int {
	b := x.Bytes()
	if len(b) == 0 {
		return big.NewInt(0)
	}

	if ceilDiv(len(b), 64) < ceilDiv(i, 64) {
		return big.NewInt(0)
	}

	return nil
}

//func (m *Montgomery) Red(z *big.Int) *big.Int {
//	r := new(big.Int).Set(z)
//	uiN := new(big.Int)
//
//	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
//		ui := getLimb(m.n, 0) * m.o
//		uii := uToInt(ui)
//
//		uiN.Mul(m.n, uii)
//		r.Add(r, uiN)
//
//		r.Rsh(r, BYTES_PER_LIMB)
//	}
//
//	if r.Cmp(m.n) >= 0 {
//		r.Sub(r, m.n)
//	}
//
//	return r
//}
//
//func (m *Montgomery) Mul(x, y *big.Int) *big.Int {
//	r := big.NewInt(0)
//
//	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
//		ui := (getLimb(r, 0) + (getLimb(y, i) * getLimb(x, 0))) * m.o
//		//fmt.Printf(">>%v\n", getLimb(x, 0))
//		//fmt.Printf(">>%v\n", getLimb(x, 0))
//
//		yix := new(big.Int).Mul(x, uToInt(getLimb(y, i)))
//		uiN := new(big.Int).Mul(m.n, uToInt(ui))
//
//		r.Add(r, yix)
//		r.Add(r, uiN)
//
//		r.Rsh(r, 8)
//	}
//
//	if r.Cmp(m.n) >= 0 {
//		r.Sub(r, m.n)
//	}
//
//	return r
//}
//
//func (m *Montgomery) Exp(x, y *big.Int) *big.Int {
//	t_hat := m.Mul(big.NewInt(1), m.ro2)
//	fmt.Printf(">%s\n", t_hat)
//	x_hat := m.Mul(x, m.ro2)
//
//	for i := 0; i < ceilDiv(len(y.Bytes()), BYTES_PER_LIMB); i++ {
//		t_hat.Mul(t_hat, t_hat)
//
//		if getLimb(y, i) > 0 {
//			t_hat.Mul(y, x_hat)
//		}
//	}
//
//	return t_hat.Mul(t_hat, big.NewInt(1))
//}

func getLimb(z *big.Int, s int) *big.Int {
	b := z.Bytes()
	if s > ceilDiv(len(b), 64) || len(b) == 0 {
		return big.NewInt(0)
	}

	//fmt.Printf(">%d\n", s)
	//fmt.Printf(">%d\n", len(b))
	//fmt.Printf(">%d\n", ceilDiv(len(b), 64))
	//fmt.Printf(">%v\n", b)

	if len(b) < BYTES_PER_LIMB*(s+1) {
		tmp := make([]byte, BYTES_PER_LIMB*(s+1))
		copy(tmp[len(tmp)-len(b):len(tmp)], b)
		b = tmp
	}
	//fmt.Printf(">%d\n", s)
	//fmt.Printf(">%d\n", len(b))
	//fmt.Printf(">%d\n", ceilDiv(len(b), 64))
	//fmt.Printf(">%v\n", b)
	//fmt.Printf("\n")

	//fmt.Printf(">%d\n", s)
	s = len(b) - ((s + 1) * BYTES_PER_LIMB)
	//fmt.Printf(">%d\n", s)
	//fmt.Printf(">%d\n", len(b))
	//fmt.Printf(">%v\n", b[s:s+BYTES_PER_LIMB])

	//s *= BYTES_PER_LIMB

	return new(big.Int).SetBytes(b[s : s+BYTES_PER_LIMB])
	//return big.NewInt(int64(binary.BigEndian.Uint64(b[s : s+BYTES_PER_LIMB])))
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
