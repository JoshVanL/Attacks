package main

import (
	"fmt"
	"big"
	"encoding/hex"
	"bytes"
	"os"

	"./utils"
	"./time_c"
	"./command"
	"./montgomery"
)

const (
	WORD_LENGTH = 256
)

type Attack struct {
	cmd  *command.Command
	conf *time_c.Conf

	interactions int

	samples []*Sample
	mnt     *montgomery.Montgomery
	d       *big.Int
}

type Sample struct {
	time    []byte
	message []byte
	mont    *big.Int
	curr    *big.Int
}

func NewAttack() (attack *Attack, err os.Error) {
	args, err := utils.ParseArguments()
	if err != nil {
		return nil, err
	}

	conf, err := time_c.NewConf(args[1])
	if err != nil {
		return nil, err
	}

	cmd, err := command.NewCommand(args[0])
	if err != nil {
		return nil, err
	}

	return &Attack{
		conf: conf,
		cmd: cmd,
		interactions: 0,
		mnt: montgomery.NewMontgomery(conf.N),
		d: big.NewInt(1),
	},
		nil
}


func (a *Attack) Write(c []byte) os.Error {
	if err := a.cmd.WriteStdin(c); err != nil {
		return utils.Error("failed to write ciphertext ", err)
	}

	return nil
}

func (a *Attack) Read() (m []byte, t []byte, err os.Error) {
	b, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, nil, utils.Error("failed to read stdout file", err)
	}

	split := bytes.Split(b, []byte{'\n'}, 3)
	if len(split) != 3 {
		return nil, nil, utils.NewError(fmt.Sprintf("got unexpected number of splits from read. exp=3 got=%d\n", len(split)))
	}

	return split[1], split[0], nil
}

func (a *Attack) Interact(c *big.Int) (m []byte, t []byte, err os.Error) {
	n := make([]byte, len(c.Bytes())*2)
	hex.Encode(n, c.Bytes())
	n = utils.Pad(bytes.AddByte(n, '\n'), WORD_LENGTH)
	//fmt.Printf(">%s>", n)

	if err := a.Write(n); err != nil {
		return nil, nil, err
	}

	m, t, err = a.Read()
	if err != nil {
		return nil, nil, err
	}

	a.interactions++

	return m, t, nil
}

func (a *Attack) generate_samples() os.Error {
	a.samples = make([]*Sample, 1300)
	for i := 0; i < 1300; i++ {
		c := utils.RandInt(a.conf.N)
		mnt, _ := a.mnt.Mul(c, a.mnt.Ro2)
		curr := a.mnt.Exp(mnt, a.d)
		time, message, err := a.Interact(c)
		if err != nil {
			return utils.Error("error interacting with program", err)
		}

		a.samples[i] = &Sample{
			time: time,
			message: message,
			mont: mnt,
			curr: curr,
		}
	}

	return nil
}

func (a *Attack) Run() os.Error {
	if err := a.cmd.Run(); err != nil {
		return err
	}

	fmt.Printf("Generating samples...")
	if err := a.generate_samples(); err != nil {
		return utils.Error("failed to generate samples", err)
	}
	fmt.Printf("done.\n")

	//f := a.mnt.Mul(a.conf.E, a.conf.N)
	//fmt.Printf("%s\n", f.String())

	//N := new(big.Int).SetBytes([]byte{255, 0, 0, 0, 0, 0, 0, 0})

	//c := big.NewInt(2)

	//for {
	//	n := utils.Pad(utils.IntToHex(c), WORD_LENGTH)

	//	if err := a.cmd.WriteStdin(n); err != nil {
	//		return utils.Error("failed to write cipher", err)
	//	}

	//	b, err := a.cmd.ReadStdout()
	//	if err != nil {
	//		return utils.Error("failed to read message", err)
	//	}

	//	m, t := utils.SplitBytes(b, '\n')
	//	t, _ = utils.SplitBytes(t, '\n')
	//	fmt.Printf("cipher:  %s", string(n))
	//	fmt.Printf("message: %s\n", string(m))
	//	fmt.Printf("time:    %s\n", string(t))

	//	c.Mul(c, c)
	//}

	return nil
}

func main() {
	fmt.Printf("Initalising attack...")
	a, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")

	if err := a.Run(); err != nil {
		utils.Fatal(err)
	}
}
