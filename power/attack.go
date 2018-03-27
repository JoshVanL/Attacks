///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package main

import (
	"bytes"
	"encoding/hex"
	//"crypto/aes"
	//"time"
	"fmt"
	"os"

	"./command"
	//"./fault_c"
	"./utils"
)

type Attack struct {
	cmd *command.Command

	//conf *fault_c.Conf

	//c_org []byte
	//m_org []byte

	interactions int
}

func main() {
	fmt.Printf("Initialising attack...")
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
		//conf: fault_c.NewConf(),
	},
		nil
}

func (a *Attack) Run() os.Error {
	fmt.Printf("Executing Attack.\n")

	if err := a.cmd.Run(); err != nil {
		return err
	}
	defer a.cmd.Kill()

	m, p, err := a.Interact(1, utils.RandInt(2, 200).Bytes())
	if err != nil {
		return err
	}

	fmt.Printf("%v\n", m)
	fmt.Printf("%v\n", p)

	return nil
}

func (a *Attack) Interact(j int, i []byte) ([]byte, []byte, os.Error) {
	if err := a.Write(j, i); err != nil {
		return nil, nil, err
	}

	p, m, err := a.Read()
	if err != nil {
		return nil, nil, err
	}

	a.interactions++

	return p, m, nil

}

func (a *Attack) Write(blockAddr int, sectorAddr []byte) os.Error {
	fmt.Printf("%v\n", []byte{byte(blockAddr), '\n'})
	fmt.Printf("%v\n", bytes.AddByte(sectorAddr, '\n'))

	m := make([]byte, len(sectorAddr)*2)
	hex.Encode(m, sectorAddr)
	m = bytes.AddByte(m, '\n')

	if err := a.cmd.WriteStdin([]byte{byte(blockAddr), '\n'}); err != nil {
		return utils.Error("failed to write block adress", err)
	}

	if err := a.cmd.WriteStdin(m); err != nil {
		return utils.Error("failed to write sector address", err)
	}

	return nil
}

func (a *Attack) Read() ([]byte, []byte, os.Error) {
	p, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, nil, utils.Error("failed to read power consumption", err)
	}

	m, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, nil, utils.Error("failed to read message", err)
	}

	i, err := utils.BytesToInt(utils.TrimLeft(m))
	if err != nil {
		return nil, nil, utils.Error("failed to convert message to int", err)
	}

	return p, i.Bytes(), err
}
