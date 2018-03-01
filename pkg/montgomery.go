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

func Ro(N *big.Int) *big.Int {
	b := big.NewInt(2)
	n := N.Len()

	return new(big.Int).Exp(b, big.NewInt(int64(n)), nil)
}

func Reduction(m, t *big.Int) *big.Int {

	b := big.NewInt(2)
	n := m.Len()

	R := new(big.Int).Exp(b, big.NewInt(int64(n)), nil)

	nm := new(big.Int).Neg(m)
	if nm.Cmp(big.NewInt(0)) < 0 {
		nm.Add(nm, R)
	}
	nm = nm.Mod(nm, R)
	mp := ModInverse(nm, R)

	A := new(big.Int).Set(t)

	ui := mp.Mod(mp, b)
	ui = ui.Mul(ui, m)
	bi := new(big.Int)
	for i := 0; i < n; i++ {
		ai := bit(A, i)
		if ai == 1 {
			bi = bi.Exp(b, big.NewInt(int64(i)), nil)
			ad := new(big.Int).Mul(ui, bi)
			A = A.Add(A, ad)
		}
	}

	r := new(big.Int).Rsh(A, n)
	if cmp := r.Cmp(m); cmp == 0 || cmp == 1 {
		r = r.Sub(r, m)
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

func MontgomeryMul(x, y, m *big.Int) (*big.Int, int) {

	if x.Cmp(m) == 1 || y.Cmp(m) == 1 {
		return x, -1
	}

	b := big.NewInt(2)
	n := m.Len()

	R := new(big.Int).Exp(b, big.NewInt(int64(n)), nil)

	nm := new(big.Int).Neg(m)
	if nm.Cmp(big.NewInt(0)) < 0 {
		nm.Add(nm, R)
	}
	nm = nm.Mod(nm, R)
	mp := ModInverse(nm, R)

	A := big.NewInt(0)

	ui := new(big.Int).Mod(mp, b)
	ui = ui.Mul(ui, m)

	y0 := big.NewInt(int64(bit(y, 0)))

	for i := 0; i < n; i++ {

		a0 := big.NewInt(int64(bit(A, 0)))
		xi := big.NewInt(int64(bit(x, i)))
		ui := new(big.Int).Mul(xi, y0)
		ui.Add(ui, a0)
		ui.Mul(ui, mp)
		ui.Mod(ui, b)
		ui.Mul(ui, m)

		ad := new(big.Int).Mul(xi, y)
		ad.Add(ad, ui)
		ad.Add(ad, A)
		a := new(big.Int).Rsh(ad, 1)
		A = a
	}

	extra := 0
	//The big bad "extra reduction" step :)
	if A.Cmp(m) >= 0 {
		A.Sub(A, m)
		extra = 1
	}
	A = A.Mul(A, R)

	A = A.Mod(A, m)

	return A, extra
}
func montgomeryMul(x, y, m *big.Int) (*big.Int, int) {

	if x.Cmp(m) == 1 || y.Cmp(m) == 1 {
		return x, -1
	}

	b := big.NewInt(2)
	n := m.Len()

	R := new(big.Int).Exp(b, big.NewInt(int64(n)), nil)

	nm := new(big.Int).Neg(m)
	if nm.Cmp(big.NewInt(0)) < 0 {
		nm.Add(nm, R)
	}
	nm = nm.Mod(nm, R)
	mp := ModInverse(nm, R)

	A := big.NewInt(0)

	ui := new(big.Int).Mod(mp, b)
	ui = ui.Mul(ui, m)

	y0 := big.NewInt(int64(bit(y, 0)))

	for i := 0; i < n; i++ {

		a0 := big.NewInt(int64(bit(A, 0)))
		xi := big.NewInt(int64(bit(x, i)))
		ui := new(big.Int).Mul(xi, y0)
		ui.Add(ui, a0)
		ui.Mul(ui, mp)
		ui.Mod(ui, b)
		ui.Mul(ui, m)

		ad := new(big.Int).Mul(xi, y)
		ad.Add(ad, ui)
		ad.Add(ad, A)
		a := new(big.Int).Rsh(ad, 1)
		A = a
	}

	extra := 0
	//The big bad "extra reduction" step :)
	if A.Cmp(m) >= 0 {
		A.Sub(A, m)
		extra = 1
	}

	return A, extra
}

func MontgomeryExp(x, e, m *big.Int) (*big.Int, int) {
	if x.Cmp(m) == 1 {
		return x, -1
	}

	b := big.NewInt(2)
	n := m.Len()
	R := new(big.Int).Exp(b, big.NewInt(int64(n)), nil)
	R2 := new(big.Int).Exp(R, b, m)
	A := R.Mod(R, m)
	xs, _ := montgomeryMul(x, R2, m)

	//extras tracks how many "extra reductions" where performed
	//over the course of the exponentiation.
	extras := 0
	extra := 0
	for i := e.Len(); i >= 0; i-- {
		A, extra = montgomeryMul(A, A, m)
		extras += extra
		if bit(e, i) == 1 {
			A, extra = montgomeryMul(A, xs, m)
			extras += extra
		}
		extra = 0
	}
	A, extra = montgomeryMul(A, big.NewInt(1), m)

	extras += extra

	return A, extras
}

func bit(x *big.Int, i int) uint {
	b := x.Bytes()
	if len(b) == 0 {
		return 0
	}

	if len(b) < (i/8)+1 {
		return 0
	}

	n := uint64(b[len(b)-1-(i/8)])
	return uint((n >> (uint(i % 8))) & 1)
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

	return nil
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
