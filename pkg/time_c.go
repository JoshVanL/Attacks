package time_c

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

	return conf, nil
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
