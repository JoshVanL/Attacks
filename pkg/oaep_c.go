package oaep_c

import (
	"big"
	"os"

	"./utils"
	"./file"
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
