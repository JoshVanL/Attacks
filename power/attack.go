///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package main

import (
	"fmt"
	"os"
	"big"
	"strings"
	"bytes"
	"strconv"

	"./command"
	"./utils"
)

type Attack struct {
	cmd *command.Command

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
	},
		nil
}

func (a *Attack) Run() os.Error {
	fmt.Printf("Executing Attack.\n")

	if err := a.cmd.Run(); err != nil {
		return err
	}
	defer a.cmd.Kill()

	l, ss, m, err := a.Interact(254, big.NewInt(100).Bytes())
	if err != nil {
		return err
	}

	if l != len(ss) {
		return utils.NewError(fmt.Sprintf("l and length of trace, l=%d len(ss)=%d", l, len(ss)))
	}

	fmt.Printf("%d\n", len(ss))
	fmt.Printf("%s\n", m)
	fmt.Printf("%d\n", l)

	return nil
}

func (a *Attack) Interact(j int, i []byte) (l int, ss []int, m []byte, err os.Error) {
	if err := a.Write(j, i); err != nil {
		return -1, nil, nil, err
	}

	l, ss, m, err = a.Read()
	if err != nil {
		return -1, nil, nil, err
	}

	a.interactions++

	return l, ss, m, nil
}

func (a *Attack) Write(blockAddr int, sectorAddr []byte) os.Error {
	i := utils.Pad(bytes.AddByte(sectorAddr, '\n'), 32)
	j := utils.AppendByte(utils.IntToBytes(blockAddr), '\n')

	if err := a.cmd.WriteStdin(j); err != nil {
		return utils.Error("failed to write block adress", err)
	}

	if err := a.cmd.WriteStdin(i); err != nil {
		return utils.Error("failed to write sector address", err)
	}

	return nil
}

func (a *Attack) Read() (l int, ss []int, m []byte, err os.Error) {
	p, err := a.cmd.ReadStdout()
	if err != nil {
		return -1, nil, nil, utils.Error("failed to read power consumption", err)
	}

	str := strings.Split(fmt.Sprintf("%s", p), ",", 0)
	l, err = strconv.Atoi(str[0])
	if err != nil {
		return -1, nil, nil, utils.Error("failed to convert power length integer string", err)
	}

	start := 0
	for i, b := range p {
		if b == ',' {
			start = i + 1
			break
		}
	}

	var tmp int
	for _, b := range p[start:] {
		if b != ',' {
			tmp = 10*tmp + (int(b) - 48)
		} else {
			ss = utils.AppendInt(ss, tmp)
			tmp = 0
		}
	}

	for {
		p, err := a.cmd.ReadStdout()
		if err != nil {
			return -1, nil, nil, utils.Error("failed to read power consumption", err)
		}
		for i, b := range p {
			if b == '\n' {
				if tmp != 0 {
					ss = utils.AppendInt(ss, tmp)
				}
				m = bytes.Split(p[i+1:], []byte{'\n'}, 0)[0]

				return l, ss, m, nil
			}

			if b != ',' {
				tmp = 10*tmp + (int(b) - 48)
			} else {
				ss = utils.AppendInt(ss, tmp)
				tmp = 0
			}
		}
	}

	return
}
