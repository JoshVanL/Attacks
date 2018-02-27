package oaep_c

import (
	"big"
	"os"
	"math"
	//"fmt"
	"crypto/sha1"

	"./utils"
	"./file"
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

	// B = 2 ^ (8 * (k-1))
	conf.B = new(big.Int)
	conf.B.Sub(conf.K, big.NewInt(1))
	conf.B.Mul(conf.B, big.NewInt(8))
	conf.B.Exp(big.NewInt(2), conf.B, nil)

	return conf, nil
}

func (c *Conf) RSAf(f *big.Int) *big.Int {
	z := new(big.Int)
	z.Exp(f, c.E, c.N)
	z.Mul(z, c.C)
	z = z.Mod(z, c.N)

	return z
}

func (c *Conf) I2OSP(x int64, l int64) (X []byte, err os.Error) {
	// Should be 256 but we're doing hex
	if x >= int64(math.Pow(256, float64(l))) {
		return nil, utils.NewError("integer too large")
	}

	var p int64
	var n int64
	X = make([]byte, l)

	index := 0
	for i := l - 1; i >= 0; i-- {
		// Should be 256 but we're doing hex
		p = int64(math.Pow(256, float64(i)))
		n = x / p
		x = x % p
		//X[index] = utils.ZToHex(big.NewInt(n))
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
	T := make([]byte, hLen)

	//fmt.Printf("l:%d\n", l)
	//fmt.Printf("h:%d\n", hLen)
	//fmt.Printf("l:%d\n", l/hLen)
	for i := int64(0); i < l/hLen; i++ {
		// use hex 8 instead of 4 so we can read it
		C, err := c.I2OSP(i, 4)
		if err != nil {
			return nil, err
		}

		//fmt.Printf("Z%s\n", string(Z))
		Z = utils.AppendByteSlice(Z, C)
		//fmt.Printf("C%s\n", string(C))
		//fmt.Printf("Z%s\n", string(Z))
		_, err = hash.Write(Z)
		if err != nil {
			return nil, err
		}

		h := hash.Sum()
		//fmt.Printf("C%s\n", string(C))
		//fmt.Printf("h%s\n", string(h))
		//fmt.Printf("T%s\n", string(T))

		T = utils.AppendByteSlice(T, h)
		//fmt.Printf("T%s\n", string(T))
		hash.Reset()
	}

	return T[0:l], nil
}
