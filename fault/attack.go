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
	"os"

	"./command"
	"./fault_c"
	"./utils"
)

const (
	WORD_LENGTH = 16
	KEY_RANGE   = 256
	BYTES       = 16
)

type Attack struct {
	cmd *command.Command

	conf *fault_c.Conf

	c_org *big.Int
	m_org *big.Int

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

	c := utils.RandInt(2, 128)
	m, err := a.Interact(c, []byte{'\n'})
	if err != nil {
		return err
	}

	a.c_org = c
	a.m_org = m

	hypotheses, _, err := a.GenerateHypothesis()
	if err != nil {
		return err
	}

	//fmt.Printf("%d\n", len(hypotheses))
	//fmt.Printf("%s\n", m_f)

	_, err = a.AttackMultiFault(hypotheses)
	if err != nil {
		return err
	}

	if err := a.cmd.Kill(); err != nil {
		return err
	}

	return nil
}

func (a *Attack) AttackMultiFault(hypotheses [][]byte) (k *big.Int, err os.Error) {

	for a.maxByteLength(hypotheses) > 1 {

		curr_hypothesis, _, err := a.GenerateHypothesis()
		if err != nil {
			return nil, utils.Error("failed to generate current hypotheses", err)
		}

		var next_hypothesis [][]byte

		for _, byte_current := range curr_hypothesis {

			var matching_keys []byte
			for _, byte_previous := range hypotheses {
				for _, keys_current := range byte_current {
					for _, keys_previous := range byte_previous {

						if keys_current == keys_previous {
							//fmt.Printf("%T\n", keys_current)
							matching_keys = utils.AppendByte(matching_keys, keys_current)
						}
					}
				}
			}

			next_hypothesis = utils.AppendBytesSlices(next_hypothesis, matching_keys)
		}

		hypotheses = next_hypothesis
	}

	fmt.Printf("%v\n", hypotheses)

	return nil, nil
}

func (a *Attack) GenerateHypothesis() (hypotheses [][]byte, m_f *big.Int, err os.Error) {
	f := a.conf.BuildFault(8, 1, 0, 0, 0)

	m_f, err = a.Interact(a.c_org, f)
	if err != nil {
		return nil, nil, err
	}

	HV := make([][][]byte, BYTES)
	for i := range HV {
		HV[i] = make([][]byte, KEY_RANGE)
	}

	for i := 0; i < 16; i++ {
		var d_mult []byte
		if utils.Contains([]int{0, 2, 9, 11}, i) {
			d_mult = a.conf.Delta2()
		} else if utils.Contains([]int{5, 7, 12, 14}, i) {
			d_mult = a.conf.Delta3()
		} else if utils.Contains([]int{1, 3, 4, 6, 8, 10, 13, 15}, i) {
			d_mult = a.conf.Delta1()
		}

		for k := 0; k < 256; k++ {
			delt_i := a.conf.SBoxInv()[utils.XORToInt(a.m_org.Bytes()[i], k)] ^ a.conf.SBoxInv()[utils.XORToInt(m_f.Bytes()[i], k)]

			for j, delt := range d_mult {
				if delt_i == delt {
					HV[i][j] = utils.AppendByte(HV[i][j], byte(k))
				}
			}
		}
	}

	//fmt.Printf("%d\n", len(HV[0][0]))
	hypotheses = make([][]byte, 4)

	for cnt, bytes := range [][]byte{[]byte{0, 13, 10, 7}, []byte{4, 1, 14, 11}, []byte{8, 5, 2, 15}, []byte{12, 9, 6, 3}} {
		for i := 0; i < KEY_RANGE; i++ {

			if (len(HV[bytes[0]][i]) > 0) && (len(HV[bytes[1]][i]) > 0) && (len(HV[bytes[2]][i]) > 0) && (len(HV[bytes[3]][i]) > 0) {

				//fmt.Printf("\n")
				//fmt.Printf("%d\n", len(HV[bytes[0]][i]))
				//fmt.Printf("%d\n", len(HV[bytes[1]][i]))
				//fmt.Printf("%d\n", len(HV[bytes[2]][i]))
				//fmt.Printf("%d\n", len(HV[bytes[3]][i]))
				//fmt.Printf("\n")
				// TODO: Fix this
				//for j := 0; j < len(HV[bytes[1]][i]); j++ {
				for j := 0; j < 2; j++ {
					hyp := make([]byte, 4)
					hyp[0] = HV[bytes[0]][i][j]
					hyp[1] = HV[bytes[1]][i][j]
					hyp[2] = HV[bytes[2]][i][j]
					hyp[3] = HV[bytes[3]][i][j]
					hypotheses[cnt] = utils.AppendByteSlice(hypotheses[cnt], hyp)
				}
				//fmt.Printf("%d\n", len(hypotheses[0]))
			}
		}
	}

	//fmt.Printf("%s\n", m)
	//fmt.Printf("%s\n", c)
	//fmt.Printf("%s\n", x)

	return hypotheses, m_f, nil
}

func (a *Attack) Interact(message *big.Int, fault []byte) (*big.Int, os.Error) {
	m := make([]byte, len(message.Bytes())*2)
	hex.Encode(m, message.Bytes())
	m = utils.Pad(bytes.AddByte(m, '\n'), WORD_LENGTH)

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

func (a *Attack) maxByteLength(bs [][]byte) int {
	l := 0

	for _, b := range bs {
		if len(b) > l {
			l = len(b)
		}
	}

	return l
}
