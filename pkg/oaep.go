package oaep

import (
	"big"
	"bufio"
	"os"
	"syscall"

	"./utils"
)

const (
	NewLine = byte(10)
	Base    = 16
)

type Conf struct {
	Fields []string
	Bytes  [][]byte

	N *big.Int
	E *big.Int
	L *big.Int
	C *big.Int

	K *big.Int
	B *big.Int

	reader *bufio.Reader
}

func NewConf(filename string) (*Conf, os.Error) {
	f, err := os.Open(filename, syscall.O_RDONLY, 666)
	if err != nil {
		return nil, utils.Error("failed to read conf file", err)
	}

	conf := &Conf{
		reader: bufio.NewReader(f),
	}

	if conf.N, err = conf.readNum(); err != nil {
		return nil, utils.Error("failed to get N", err)
	}

	if conf.E, err = conf.readNum(); err != nil {
		return nil, utils.Error("failed to get e", err)
	}

	if conf.L, err = conf.readNum(); err != nil {
		return nil, utils.Error("failed to get l", err)
	}

	if conf.C, err = conf.readNum(); err != nil {
		return nil, utils.Error("failed to get c", err)
	}

	conf.K = big.NewInt(int64(len(conf.Fields[0]) / 2))

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

func (c *Conf) readNum() (*big.Int, os.Error) {
	b, err := c.readBytes()
	if err != nil {
		return nil, err
	}

	z := new(big.Int)
	_, ok := z.SetString(string(b), Base)
	if !ok {
		return nil, os.NewError("failed to convert conf value to hex")
	}

	return z, nil
}

func (c *Conf) readBytes() ([]byte, os.Error) {
	b, err := c.reader.ReadBytes(NewLine)
	if err != nil {
		return nil, utils.Error("fauled to read bytes from file", err)
	}

	c.Fields = utils.Append(c.Fields, string(b))
	c.Bytes = utils.AppendBytes(c.Bytes, b)

	// Remove trailing new line
	return b[0 : len(b)-1], nil
}
