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
	"time"
	"fmt"
	"os"

	"./command"
	"./fault_c"
	"./utils"
)

//[[[161 232 6 106]] [[212 51 240 121] [170 196 66 235] [167 33 48 184]]
//[[[161 232 6 106]] [[212 51 240 121]] [[170 196 66 235]] [[167 33 48 184]]]

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
		conf: fault_c.NewConf(),
	},
		nil
}

func (a *Attack) Run() os.Error {
	fmt.Printf("Executing Attack.\n")

	if err := a.cmd.Run(); err != nil {
		return err
	}

	now := time.Nanoseconds()

	c := utils.RandInt(2, 128)
	m, err := a.Interact(c, []byte{'\n'})
	if err != nil {
		return err
	}

	a.c_org = c
	a.m_org = m

	fmt.Printf("Generating Initial Hypothesis...")
	hypotheses, _, err := a.GenerateHypothesis()
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")

	_, err = a.AttackMultiFault(hypotheses)
	if err != nil {
		return err
	}

	if err := a.cmd.Kill(); err != nil {
		return err
	}

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func (a *Attack) AttackMultiFault(hypotheses [][][]byte) (k *big.Int, err os.Error) {

	i := 1

	for utils.MaxLen3ByteSlice(hypotheses) > 1 {

		fmt.Printf("\rCalculating Next Hypothesis [%d]...", i)
		i++

		curr_hypothesis, _, err := a.GenerateHypothesis()
		if err != nil {
			return nil, utils.Error("failed to generate current hypotheses", err)
		}

		var next_hypothesis [][][]byte

		for _, byte_current := range curr_hypothesis {

			var matching_keys [][]byte
			for _, byte_previous := range hypotheses {
				for _, keys_current := range byte_current {
					for _, keys_previous := range byte_previous {

						if a.sameKey(keys_current, keys_previous) {
							matching_keys = utils.AppendByte2(matching_keys, keys_current)
						}

					}
				}
			}

			next_hypothesis = utils.AppendByte3(next_hypothesis, matching_keys)
		}

		hypotheses = next_hypothesis
	}

	fmt.Printf("done.\n")

	fmt.Printf("%v\n", hypotheses)

	return nil, nil
}

func (a *Attack) GenerateHypothesis() (hypotheses [][][]byte, m_f *big.Int, err os.Error) {
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

	hypotheses = make([][][]byte, 4)

	for cnt, bytes := range [][]byte{[]byte{0, 13, 10, 7}, []byte{4, 1, 14, 11}, []byte{8, 5, 2, 15}, []byte{12, 9, 6, 3}} {
		for i := 0; i < KEY_RANGE; i++ {

			if (len(HV[bytes[0]][i]) > 0) && (len(HV[bytes[1]][i]) > 0) && (len(HV[bytes[2]][i]) > 0) && (len(HV[bytes[3]][i]) > 0) {

				for _, key0 := range HV[bytes[0]][i] {
					for _, key1 := range HV[bytes[1]][i] {
						for _, key2 := range HV[bytes[2]][i] {
							for _, key3 := range HV[bytes[3]][i] {
								hypotheses[cnt] = utils.AppendByte2(hypotheses[cnt], []byte{key0, key1, key2, key3})
							}
						}
					}
				}
			}
		}
	}

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

func (a *Attack) sameKey(k1 []byte, k2 []byte) bool {
	if len(k1) != len(k2) {
		return false
	}

	for i := range k1 {
		if k1[i] != k2[i] {
			return false
		}
	}

	return true
}
