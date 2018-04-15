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
	"crypto/aes"
	"time"
	"fmt"
	"os"

	"./command"
	"./fault_c"
	"./utils"
)

const (
	WORD_LENGTH = 16
	KEY_RANGE   = 256
)

type Attack struct {
	cmd *command.Command

	conf *fault_c.Conf

	c_org []byte
	m_org []byte

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
	defer a.cmd.Kill()

	now := time.Nanoseconds()

	fmt.Printf("Generating Initial Hypothesis...")
	m := utils.RandInt(2, 128).Bytes()
	c, err := a.Interact(m, []byte{'\n'})
	if err != nil {
		return err
	}

	a.c_org = c
	a.m_org = m

	hypotheses, err := a.GenerateHypothesis()
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")

	h, err := a.AttackFault(hypotheses)
	if err != nil {
		return err
	}

	fmt.Printf("Reconstructing Key...")
	d := a.ConstructKey(h)
	fmt.Printf("done.\n")

	fmt.Printf("Checking Key...")
	correct, err := a.CheckKey(d)
	if err != nil {
		return err
	}
	if !correct {
		return utils.NewError("key incorrect, does not produce same texts.")
	}
	fmt.Printf("done.\n")

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)
	fmt.Printf("Target material: [%X]\n", d)
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}


func (a *Attack) GenerateHypothesis() (hypotheses [][][]byte, err os.Error) {
	f := a.conf.BuildFault(8, 1, 0, 0, 0)

	m_f, err := a.Interact(a.m_org, f)
	if err != nil {
		return nil, err
	}

	HV := make([][][]byte, WORD_LENGTH)
	for i := range HV {
		HV[i] = make([][]byte, KEY_RANGE)
	}

	for i := 0; i < WORD_LENGTH; i++ {
		var d_m []byte
		if utils.Contains([]int{0, 2, 9, 11}, i) {
			d_m = a.conf.Delta2()
		} else if utils.Contains([]int{5, 7, 12, 14}, i) {
			d_m = a.conf.Delta3()
		} else if utils.Contains([]int{1, 3, 4, 6, 8, 10, 13, 15}, i) {
			d_m = a.conf.Delta1()
		}

		for k := 0; k < 256; k++ {
			d_i := a.conf.SBoxInv()[utils.XORToInt(a.c_org[i], k)]
			d_i ^= a.conf.SBoxInv()[utils.XORToInt(m_f[i], k)]

			for j, delt := range d_m {
				if d_i == delt {
					HV[i][j] = utils.AppendByte(HV[i][j], byte(k))
				}
			}
		}
	}

	return a.collectValidHypotheses(HV), nil
}

func (a *Attack) AttackFault(hypotheses [][][]byte) ([][][]byte, os.Error) {
	var err os.Error
	i := 1

	for utils.MaxLen3ByteSlice(hypotheses) > 1 {
		fmt.Printf("\rCalculating Next Hypothesis [%d]...", i)

		hypotheses, err = a.calculateNextHypothosis(hypotheses)
		if err != nil {
			return nil, utils.Error(fmt.Sprintf("error calculating [%d] hypothesis", i), err)
		}

		i++
	}

	fmt.Printf("done.\n")

	return hypotheses, nil
}

func (a *Attack) ConstructKey(hypotheses [][][]byte) []byte {
	// Reconstruct
	var off int
	b := make([]byte, WORD_LENGTH)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			b[(i*4)+j] = hypotheses[(i+j)%4][0][j]
		}
		off++
	}

	// Inverse Key
	for i := 10; i > 0; i-- {

		tmp := make([]byte, 12)
		for j := 0; j < 12; j++ {
			tmp[j] = b[j] ^ b[j+4]
		}
		copy(b[4:len(b)], tmp)

		b[1] = a.conf.SBox()[b[14]] ^ b[1]
		b[2] = a.conf.SBox()[b[15]] ^ b[2]
		b[3] = a.conf.SBox()[b[12]] ^ b[3]

		b[0] = a.conf.SBox()[b[13]] ^ b[0] ^ a.conf.RoundConstant()[i]
	}

	return b
}

func (a *Attack) CheckKey(d []byte) (bool, os.Error) {
	k, err := aes.NewCipher(d)
	if err != nil {
		return false, utils.Error("failed to construct AES key from key bytes", err)
	}

	m := make([]byte, WORD_LENGTH)

	k.Decrypt(a.c_org, m)
	if !a.sameBytes(m, a.m_org) {
		return false, nil
	}

	k.Encrypt(a.m_org, m)
	if !a.sameBytes(m, a.c_org) {
		return false, nil
	}

	return true, nil
}

func (a *Attack) calculateNextHypothosis(hypotheses [][][]byte) ([][][]byte, os.Error) {
	curr_hypothesis, err := a.GenerateHypothesis()
	if err != nil {
		return nil, utils.Error("failed to generate current hypothesis", err)
	}

	var nxt_hypothesis [][][]byte

	for _, byte_curr := range curr_hypothesis {

		var match_ks [][]byte
		for _, byte_prev := range hypotheses {
			for _, ks_curr := range byte_curr {
				for _, ks_prev := range byte_prev {

					if a.sameBytes(ks_curr, ks_prev) {
						match_ks = utils.AppendByte2(match_ks, ks_curr)
					}

				}
			}
		}

		nxt_hypothesis = utils.AppendByte3(nxt_hypothesis, match_ks)
	}

	return nxt_hypothesis, nil
}

func (a *Attack) collectValidHypotheses(HV [][][]byte) [][][]byte {
	hypotheses := make([][][]byte, 4)

	rng := [][]byte{[]byte{0, 13, 10, 7}, []byte{4, 1, 14, 11}, []byte{8, 5, 2, 15}, []byte{12, 9, 6, 3}}

	for cnt, bytes := range rng {
		for i := 0; i < KEY_RANGE; i++ {

			if (len(HV[bytes[0]][i]) > 0) && (len(HV[bytes[1]][i]) > 0) && (len(HV[bytes[2]][i]) > 0) && (len(HV[bytes[3]][i]) > 0) {
				for _, k0 := range HV[bytes[0]][i] {
					for _, k1 := range HV[bytes[1]][i] {
						for _, k2 := range HV[bytes[2]][i] {
							for _, k3 := range HV[bytes[3]][i] {
								hypotheses[cnt] = utils.AppendByte2(hypotheses[cnt], []byte{k0, k1, k2, k3})
							}
						}
					}
				}
			}
		}
	}

	return hypotheses
}

func (a *Attack) Interact(message []byte, fault []byte) ([]byte, os.Error) {
	m := make([]byte, len(message)*2)
	hex.Encode(m, message)
	m = bytes.AddByte(m, '\n')

	if err := a.Write(fault, m); err != nil {
		return nil, err
	}

	c, err := a.Read()
	if err != nil {
		return nil, err
	}

	a.interactions++

	return c, nil
}

func (a *Attack) Write(fault, message []byte) os.Error {
	if err := a.cmd.WriteStdin(fault); err != nil {
		return utils.Error("failed to write fault", err)
	}
	if err := a.cmd.WriteStdin(message); err != nil {
		return utils.Error("failed to write message", err)
	}

	return nil
}

func (a *Attack) Read() ([]byte, os.Error) {
	c, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, utils.Error("failed to read cipher text", err)
	}

	i, err := utils.BytesToInt(utils.TrimLeft(c))
	if err != nil {
		return nil, utils.Error("failed to convert cipher text to int", err)
	}

	return i.Bytes(), err
}

func (a *Attack) sameBytes(k1 []byte, k2 []byte) bool {
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
