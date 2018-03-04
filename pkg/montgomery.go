package montgomery

import (
	"big"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	BYTES_PER_LIMB = 8
	LIMB_SIZE      = 64
)

type Montgomery struct {
	n   *big.Int
	o   *big.Int
	ro  *big.Int
	ro2 *big.Int
}

func NewMontgomery(N *big.Int) *Montgomery {
	R, R2 := Ro(N)

	m := &Montgomery{
		n: N,
		ro: R,
		ro2: R2,
		o: Omega(N),
	}

	fmt.Printf("\no: %v\n", m.o)
	fmt.Printf("ro: %s\n", m.ro)
	fmt.Printf("ro2: %s\n", m.ro2)
	fmt.Printf("N: %s\n", m.n)
	foo := m.Mul(m.ro2, m.ro2)
	fmt.Printf("foo:%s\n", foo)
	os.Exit(1)

	return m
}

func Omega(N *big.Int) *big.Int {
	o := big.NewInt(1)
	//n := getLimb(N, 0)
	//foo := uint64(1)

	//fmt.Printf("N: %s\n", N)
	//fmt.Printf("o: %s\n", o)
	//fmt.Printf("N: %s\n", getLimb(N, 0))
	n := getLimb(N, 0)
	for i := 1; i < LIMB_SIZE; i++ {
		tmp := new(big.Int).Mul(o, n)
		o.Mul(o, tmp)
		o = getLimb(o, 0)
		//fmt.Printf("o: %s\n", o)
		//o *= o * n
		//tmp := new(big.Int).Mul(o, N)
		//o.Mul(o, tmp)
		//o = o.SetBytes(o.Bytes()[0:BYTES_PER_LIMB])
		//fmt.Printf("o: %d\n", getLimb(o, 0))
	}

	bytes := o.Bytes()
	ob := make([]byte, len(bytes))
	for i, b := range bytes {
		ob[i] = b ^ byte(255)
	}

	//return -getLimb(o, 0)
	// this couild be bad
	o.SetBytes(ob)
	o.Add(o, big.NewInt(1))

	return o
}

func Ro(N *big.Int) (R *big.Int, R2 *big.Int) {
	b := big.NewInt(2)
	n := N.Len()

	R = new(big.Int).Exp(b, big.NewInt(int64(n)), nil)
	R2 = new(big.Int).Exp(R, b, N)

	return R, R2
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

func (m *Montgomery) montgomeryMul(x, y, N *big.Int) (*big.Int, int) {

	if x.Cmp(N) == 1 || y.Cmp(N) == 1 {
		return x, -1
	}

	b := big.NewInt(2)
	n := N.Len()

	nm := new(big.Int).Neg(N)
	if nm.Cmp(big.NewInt(0)) < 0 {
		nm.Add(nm, m.ro)
	}
	nm = nm.Mod(nm, m.ro)
	mp := ModInverse(nm, m.ro)

	A := big.NewInt(0)

	ui := new(big.Int).Mod(mp, b)
	ui = ui.Mul(ui, N)

	y0 := big.NewInt(int64(bit(y, 0)))

	for i := 0; i < n; i++ {

		a0 := big.NewInt(int64(bit(A, 0)))
		xi := big.NewInt(int64(bit(x, i)))
		ui := new(big.Int).Mul(xi, y0)
		ui.Add(ui, a0)
		ui.Mul(ui, mp)
		ui.Mod(ui, b)
		ui.Mul(ui, N)

		ad := new(big.Int).Mul(xi, y)
		ad.Add(ad, ui)
		ad.Add(ad, A)
		a := new(big.Int).Rsh(ad, 1)
		A = a
	}

	extra := 0
	//The big bad "extra reduction" step :)
	if A.Cmp(N) >= 0 {
		A.Sub(A, N)
		extra = 1
	}

	return A, extra
}

func (m *Montgomery) MontgomeryExp(x, e *big.Int) (*big.Int, int) {
	if x.Cmp(m.n) == 1 {
		return x, -1
	}

	A := new(big.Int).Mod(m.ro, m.n)
	xs, _ := m.montgomeryMul(x, m.ro2, m.n)

	//extras tracks how many "extra reductions" where performed
	//over the course of the exponentiation.
	extras := 0
	extra := 0
	for i := e.Len(); i >= 0; i-- {
		A, extra = m.montgomeryMul(A, A, m.n)
		extras += extra
		if bit(e, i) == 1 {
			A, extra = m.montgomeryMul(A, xs, m.n)
			extras += extra
		}
		extra = 0
	}
	A, extra = m.montgomeryMul(A, big.NewInt(1), m.n)

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

//func (m *Montgomery) Red(z *big.Int) *big.Int {
//	fmt.Printf("r: %s\n", r)
//	os.Exit(1)
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

func (m *Montgomery) Mul(x, y *big.Int) *big.Int {
	r := big.NewInt(0)

	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
		//fmt.Printf("y: %s\n", y)
		//fmt.Printf("x: %s\n", x)
		//fmt.Printf("ui: %s\n", getLimb(y, i))
		//fmt.Printf("ui: %s\n", getLimb(x, 0))
		ui := new(big.Int).Mul(getLimb(y, i), getLimb(x, 0))
		ui = getLimb(ui, 0)
		//fmt.Printf("yx: %s\n", ui)
		ui.Add(ui, getLimb(r, 0))
		ui = getLimb(ui, 0)
		//fmt.Printf("ur: %s\n", ui)
		//fmt.Printf("o: %s\n", m.o)
		ui.Mul(ui, m.o)
		ui = getLimb(ui, 0)
		//fmt.Printf("ui: %s\n", ui)
		//ui := (getLimb(r, 0) + (getLimb(y, i) * getLimb(x, 0))) * m.o
		//fmt.Printf(">>%v\n", getLimb(x, 0))
		//fmt.Printf(">>%v\n", getLimb(x, 0))

		//fmt.Printf("ui: %s\n", ui)
		yix := new(big.Int).Mul(x, getLimb(y, i))
		uiN := new(big.Int).Mul(m.n, ui)
		//fmt.Printf("x: %s\n", x)
		//fmt.Printf("yi: %s\n", getLimb(y, i))
		//fmt.Printf("yi: %v\n", getLimb(y, i).Bytes())
		//fmt.Printf("yix: %s\n", yix)
		//fmt.Printf("uiN: %s\n", uiN)

		r.Add(r, yix)
		//fmt.Printf("r: %s\n", r)
		r.Add(r, uiN)
		//fmt.Printf("r: %s\n", r)

		rBytes := r.Bytes()
		b := make([]byte, len(rBytes)-8)
		b = rBytes[0:(len(rBytes) - 8)]
		r.SetBytes(b)
		//r = new(big.Int).Rsh(r, 1)
	}

	if r.Cmp(m.n) >= 0 {
		r.Sub(r, m.n)
	}

	return r
}

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
	//if s >= ceilDiv(len(z.Bytes()), BYTES_PER_LIMB) {
	//	return 0
	//}

	b := z.Bytes()
	e := len(b) - (s * 8)
	s = len(b) - 8 - (s * 8)

	if e > len(b) {
		e = len(b)
	}
	if s < 0 {
		s = 0
	}
	//fmt.Printf("s:%d\n", s)
	//fmt.Printf("e:%d\n", e)
	//fmt.Printf("b>%v\n", b)
	//fmt.Printf("b>%v\n", b[len(b)-8:len(b)])
	//fmt.Printf("b>%d\n", binary.BigEndian.Uint64(b[len(b)-8:len(b)]))
	//foo := new(big.Int).SetBytes(b[len(b)-4 : len(b)])
	//fmt.Printf("b>%s\n", foo)


	//if len(b) < BYTES_PER_LIMB {
	//	tmp := make([]byte, BYTES_PER_LIMB)
	//	copy(tmp[BYTES_PER_LIMB-len(b):BYTES_PER_LIMB], b)
	//	b = tmp
	//}
	//fmt.Printf("%v\n", b)

	//fmt.Printf("s:%d\n", s)
	//fmt.Printf("z:%s\n", z.String())
	return new(big.Int).SetBytes(b[s:e])
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
