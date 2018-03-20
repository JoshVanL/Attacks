///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package main

import (
	"big"
	"bytes"
	"encoding/hex"
	"fmt"
	//"math"
	"os"
	//"runtime"
	//"time"

	"./command"
	"./fault_c"
	"./utils"
)

const (
	WORD_LENGTH = 16
)

type Attack struct {
	cmd *command.Command

	conf *fault_c.Conf

	interactions int
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

func NewAttack() (*Attack, os.Error) {
	args, err := utils.ParseArguments()
	if err != nil {
		return nil, err
	}

	cmd, err := command.NewCommand(args[0])
	if err != nil {
		return nil, err
	}

	return &Attack{
		cmd: cmd,
		interactions: 0,
		conf: fault_c.NewConf(),
	},
		nil
}

func (a *Attack) Run() os.Error {
	fmt.Printf("Executing Attack.\n")

	if err := a.cmd.Run(); err != nil {
		return err
	}

	m := utils.RandInt(2, 128)
	c, err := a.Interact(m, []byte{'\n'})
	if err != nil {
		return err
	}

	_, err = a.GenerateHypothesis(m, c)
	if err != nil {
		return err
	}

	if err := a.cmd.Kill(); err != nil {
		return err
	}

	return nil
}

func (a *Attack) GenerateHypothesis(m *big.Int, c *big.Int) (*big.Int, os.Error) {
	f := a.conf.BuildFault(8, 1, 0, 0, 0)
	//fmt.Printf("%v\n", f)
	//fmt.Printf("%s\n", f)
	_, err := a.Interact(c, f)
	if err != nil {
		return nil, err
	}

	//var div int
	//for i := 0; i < 16; i++ {
	//	if utils.Contains([]int{0, 2, 9, 11}, i) {
	//		div = 1
	//	} else if utils.Contains([]int{5, 7, 12, 14}, i) {
	//		div = 2
	//	} else {
	//		div = 0
	//	}

	//}

	//fmt.Printf("%s\n", m)
	//fmt.Printf("%s\n", c)
	//fmt.Printf("%s\n", x)

	return nil, nil
}

func (a *Attack) Interact(message *big.Int, fault []byte) (*big.Int, os.Error) {
	m := make([]byte, len(message.Bytes())*2)
	hex.Encode(m, message.Bytes())
	m = utils.Pad(bytes.AddByte(m, '\n'), WORD_LENGTH)

	//fmt.Printf("%s\n", m)
	//fmt.Printf("%v\n", fault)

	if err := a.cmd.WriteStdin(fault); err != nil {
		return nil, utils.Error("failed to write fault", err)
	}
	if err := a.cmd.WriteStdin(m); err != nil {
		return nil, utils.Error("failed to write message", err)
	}

	c, err := a.Read()
	if err != nil {
		return nil, err
	}

	a.interactions++

	return c, nil
}

func (a *Attack) Read() (*big.Int, os.Error) {
	c, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, utils.Error("failed to read ciphertext", err)
	}

	i, err := utils.BytesToInt(utils.TrimLeft(c))
	if err != nil {
		return nil, utils.Error("failed to convert ciphertext to int", err)
	}

	return i, err
}
