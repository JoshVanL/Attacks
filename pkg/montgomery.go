///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package montgomery

import (
	"big"
	"encoding/binary"
)

const (
	WINDOW_SIZE    = 6
	BYTES_PER_LIMB = 8
	LIMB_SIZE      = 64
)

type Montgomery struct {
	n   *big.Int
	o   *big.Int
	Ro  *big.Int
	Ro2 *big.Int
}

// Initialise new Montgomery struct
func NewMontgomery(N *big.Int) *Montgomery {
	R, R2 := Ro(N)

	m := &Montgomery{
		n: N,
		Ro: R,
		Ro2: R2,
		o: Omega(N),
	}

	return m
}

// Calculate Montgomery omega
func Omega(N *big.Int) *big.Int {
	o := big.NewInt(1)
	n := getLimb(N, 0)

	for i := 1; i < LIMB_SIZE; i++ {
		tmp := new(big.Int).Mul(o, n)
		o.Mul(o, tmp)
		o = getLimb(o, 0)
	}

	bytes := o.Bytes()
	ob := make([]byte, len(bytes))
	for i, b := range bytes {
		ob[i] = b ^ byte(255)
	}

	o.SetBytes(ob)
	o.Add(o, big.NewInt(1))

	return o
}

// Calculate ro and ro squared
func Ro(N *big.Int) (R *big.Int, R2 *big.Int) {
	b := big.NewInt(2)
	n := N.Len()

	R = new(big.Int).Exp(b, big.NewInt(int64(n)), nil)
	R2 = new(big.Int).Exp(R, b, N)

	return R, R2
}

// Calculate Montgomery multiplication
func (m *Montgomery) Mul(x, y *big.Int) (r *big.Int, red bool) {
	r = big.NewInt(0)
	x0 := getLimb(x, 0)

	ui := new(big.Int)
	yix := new(big.Int)
	uiN := new(big.Int)

	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
		ui.Mul(getLimb(y, i), x0)
		ui.Add(ui, getLimb(r, 0))
		ui.Mul(ui, m.o)
		ui = getLimb(ui, 0)

		yix.Mul(x, getLimb(y, i))
		uiN.Mul(m.n, ui)

		r.Add(r, yix)
		r.Add(r, uiN)

		r = new(big.Int).Rsh(r, LIMB_SIZE)
	}

	red = false
	if r.Cmp(m.n) >= 0 {
		r.Sub(r, m.n)
		red = true
	}

	return r, red
}

// Calculate Montgomery exponentiation
func (m *Montgomery) Exp(x, y *big.Int) *big.Int {
	t_hat, _ := m.Mul(big.NewInt(1), m.Ro2)
	x_hat, _ := m.Mul(x, m.Ro2)

	x0, _ := m.Mul(x_hat, x_hat)

	T := make([]*big.Int, 32)
	T[0] = new(big.Int)
	T[0].Set(x_hat)
	for i := 1; i < 32; i++ {
		T[i] = new(big.Int)
		T[i], _ = m.Mul(T[i-1], x0)
	}

	i := (len(y.Bytes()) * BYTES_PER_LIMB) - 1
	var u int
	var l int
	WINDOW_SIZE := 6

	for i >= 0 {
		if bit(y, i) == 0 {
			l = i
			u = 0

		} else {

			l = max(i-WINDOW_SIZE+1, 0)

			for bit(y, l) == 0 {
				l++
			}

			i_limb := i / LIMB_SIZE
			i_bits := i % LIMB_SIZE
			l_limb := l / LIMB_SIZE
			l_bits := l % LIMB_SIZE

			if i_limb == l_limb {
				u = int(getWord(getLimb(y, i_limb), l_bits, i_bits))
			} else {
				ii := getWord(getLimb(y, i_limb), 0, i_bits) << uint(LIMB_SIZE-l_bits)
				ll := getWord(getLimb(y, l_limb), l_bits, LIMB_SIZE-1)
				u = int(concatonate(ii, ll))
			}

		}

		for j := 0; j < i-l+1; j++ {
			t_hat, _ = m.Mul(t_hat, t_hat)
		}
		if u != 0 {
			t_hat, _ = m.Mul(t_hat, T[(u-1)/2])
		}

		i = l - 1

	}

	return t_hat
}

// Calculate Montgomery reduction
func (m *Montgomery) Red(z *big.Int) *big.Int {
	r := new(big.Int).Set(z)

	for i := 0; i < ceilDiv(len(m.n.Bytes()), BYTES_PER_LIMB); i++ {
		ui := new(big.Int).Mul(getLimb(r, 0), m.o)
		ui = getLimb(ui, 0)

		uiN := new(big.Int).Mul(m.n, ui)

		r.Add(r, uiN)

		rBytes := r.Bytes()
		b := make([]byte, len(rBytes)-BYTES_PER_LIMB)
		b = rBytes[0:(len(rBytes) - BYTES_PER_LIMB)]
		r.SetBytes(b)
	}

	if r.Cmp(m.n) >= 0 {
		r.Sub(r, m.n)
	}

	return r
}


// Return max of two ints
func max(x, y int) int {
	if x > y {
		return x
	}

	return y
}

// Bitwise OR of two ints
func concatonate(x, y uint64) uint64 { return x | y }

// Return uint64 word of start and end bit positions of a big.Int
func getWord(x *big.Int, start, end int) uint64 {
	b := x.Bytes()
	if len(b) < 8 {
		tmp := make([]byte, 8)
		for i := 0; i < len(b); i++ {
			tmp[i+8-len(b)] = b[i]
		}
		b = tmp
	}

	u := binary.BigEndian.Uint64(b)

	return (u << (uint(LIMB_SIZE - 1 - end))) >> (uint(LIMB_SIZE - 1 - end + start))
}

// Return big.Int limb of index i
func getLimb(z *big.Int, s int) *big.Int {
	b := z.Bytes()
	e := len(b) - (s * BYTES_PER_LIMB)
	s = len(b) - BYTES_PER_LIMB - (s * BYTES_PER_LIMB)

	if s < 0 {
		s = 0
	}

	return new(big.Int).SetBytes(b[s:e])
}

// Ceiling division on ints
func ceilDiv(x, y int) int { return (x + y - 1) / y }

// Return bit of a big.Int at position i
func bit(x *big.Int, i int) uint {
	b := x.Bytes()
	if len(b) == 0 {
		return 0
	}

	if len(b) < (i/BYTES_PER_LIMB)+1 {
		return 0
	}

	n := uint64(b[len(b)-1-(i/BYTES_PER_LIMB)])
	return uint((n >> (uint(i % BYTES_PER_LIMB))) & 1)
}
