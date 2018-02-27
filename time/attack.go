package main

import (
	"fmt"
	"os"
	"big"

	"./utils"
	"./time_c"
	"./command"
)

const (
	WORD_LENGTH = 256
)

type Attack struct {
	cmd  *command.Command
	conf *time_c.Conf

	interactions int
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
	},
		nil
}

func (a *Attack) Run() os.Error {
	if err := a.cmd.Run(); err != nil {
		return err
	}

	c := big.NewInt(2)

	for {
		n := utils.Pad(utils.IntToHex(c), WORD_LENGTH)

		if err := a.cmd.WriteStdin(n); err != nil {
			return utils.Error("failed to write cipher", err)
		}

		b, err := a.cmd.ReadStdout()
		if err != nil {
			return utils.Error("failed to read message", err)
		}

		m, t := utils.SplitBytes(b, '\n')
		t, _ = utils.SplitBytes(t, '\n')
		fmt.Printf("cipher:  %s", string(n))
		fmt.Printf("message: %s\n", string(m))
		fmt.Printf("time:    %s\n", string(t))

		c.Mul(c, c)
	}

	return nil
}

func main() {
	fmt.Printf("Initalising attack...\n")
	a, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}

	if err := a.Run(); err != nil {
		utils.Fatal(err)
	}
}
