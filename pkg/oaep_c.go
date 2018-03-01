package oaep_c

import (
	"big"
	"bytes"
	"crypto/sha1"
	//"fmt"
	"math"
	"os"

	"./file"
	"./montgomery"
	"./utils"
)

const (
	MAX_LENGTH = 2 << 31
)

type Conf struct {
	N *big.Int
	E *big.Int
	L []byte
	C *big.Int

	K *big.Int
	B *big.Int

	m *montgomery.Montgomery
}

func NewConf(fileName string) (*Conf, os.Error) {
	fr, err := file.NewFileReader(fileName)
	if err != nil {
		return nil, err

	}

	conf := new(Conf)
	var k int

	if conf.N, k, err = fr.ReadIntLen(); err != nil {
		return nil, utils.Error("failed to get N", err)
	}

	if conf.E, err = fr.ReadInt(); err != nil {
		return nil, utils.Error("failed to get e", err)
	}

	if conf.L, err = fr.ReadLine(); err != nil {
		return nil, utils.Error("failed to get l", err)
	}

	if conf.C, err = fr.ReadInt(); err != nil {
		return nil, utils.Error("failed to get c", err)
	}

	if err := fr.CloseFile(); err != nil {
		return nil, err
	}

	conf.K = big.NewInt(int64(k / 2))

	conf.B = new(big.Int).Sub(conf.K, big.NewInt(1))
	conf.B.Mul(conf.B, big.NewInt(8))
	conf.B.Exp(big.NewInt(2), conf.B, nil)

	conf.m = montgomery.NewMontgomery(conf.N)

	return conf, nil
}

func (c *Conf) RSAf(f *big.Int) *big.Int {
	//z := new(big.Int).Exp(f, c.E, c.N)
	//z.Mul(z, c.C)
	//z = z.Mod(z, c.N)

	z, _ := montgomery.MontgomeryExp(f, c.E, c.N)
	z.Mul(z, c.C)
	z = z.Mod(z, c.N)

	//fmt.Printf("%s\n", f.String())
	//z := c.m.Exp(f, c.E)
	//fmt.Printf("%s\n", z.String())
	//z = c.m.Red(z)
	//fmt.Printf("%s\n", z.String())
	//os.Exit(1)

	return z
}

func (c *Conf) I2OSP(x int64, l int64) (X []byte, err os.Error) {
	if x >= int64(math.Pow(256, float64(l))) {
		return nil, utils.NewError("integer too large")
	}

	var p int64
	var n int64
	X = make([]byte, l)

	index := 0
	for i := l - 1; i >= 0; i-- {
		p = int64(math.Pow(256, float64(i)))
		n = x / p
		x = x % p
		X[index] = byte(n)
		index++
	}

	return X, nil
}

func (c *Conf) MGF1(Z []byte, l int64) (mask []byte, err os.Error) {
	if l > MAX_LENGTH {
		return nil, utils.NewError("mask too long")
	}

	hash := sha1.New()
	hLen := int64(hash.Size())
	var T []byte

	v := float64(l) / float64(hLen)
	v = math.Ceil(v)

	for i := int64(0); i < int64(v); i++ {
		hash = sha1.New()
		C, err := c.I2OSP(i, 4)
		if err != nil {
			return nil, err
		}

		z := utils.AppendByteSlice(Z, C)
		_, err = hash.Write(z)
		if err != nil {
			return nil, err
		}

		h := hash.Sum()

		T = bytes.Add(T, h)
	}

	return T[0:l], nil
}
