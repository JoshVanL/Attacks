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
	defer a.cmd.Kill()

	now := time.Nanoseconds()

	fmt.Printf("Generating Initial Hypothesis...")
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
	fmt.Printf("done.\n")

	h, err := a.AttackFault(hypotheses)
	if err != nil {
		return err
	}

	fmt.Printf("Reconstructing Key...")
	d, err := a.ConstructKey(h)
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")

	fmt.Printf("Checking Key...")
	correct, err := a.CheckKey(d)
	if err != nil {
		return err
	}
	if !correct {
		return utils.NewError("cipher text from message with key does not match.")
	}
	fmt.Printf("done.\n")

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)
	fmt.Printf("Target material: [%X]\n", d.Bytes())
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func (a *Attack) CheckKey(d *big.Int) (bool, os.Error) {
	k, err := aes.NewCipher(d.Bytes())
	if err != nil {
		return false, utils.Error("failed to construct AES key from key", err)
	}

	c := make([]byte, len(a.m_org.Bytes()))
	k.Decrypt(a.c_org.Bytes(), c)
	fmt.Printf("%X\n", c)
	fmt.Printf("%X\n", a.m_org.Bytes())
	fmt.Printf("%X\n", a.c_org.Bytes())
	fmt.Printf("%X\n", d.Bytes())
	//fmt.Printf("%v\n", k.BlockSize())
	//fmt.Printf("%v\n", len(d.Bytes()))
	//fmt.Printf("%X\n", d.Bytes())

	return true, nil
}


func (a *Attack) ConstructKey(hypotheses [][][]byte) (*big.Int, os.Error) {
	// Reconstruct
	var off int
	b := make([]byte, 16)
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

	return new(big.Int).SetBytes(b), nil
}

func (a *Attack) AttackFault(hypotheses [][][]byte) ([][][]byte, os.Error) {
	var err os.Error
	i := 1

	for utils.MaxLen3ByteSlice(hypotheses) > 1 {
		fmt.Printf("\rCalculating Next Hypothesis [%d]...", i)

		hypotheses, err = a.calculateNextHypothosis(hypotheses)
		if err != nil {
			return nil, err
		}

		i++
	}

	fmt.Printf("done.\n")

	return hypotheses, nil
}

func (a *Attack) calculateNextHypothosis(hypotheses [][][]byte) ([][][]byte, os.Error) {
	curr_hypothesis, _, err := a.GenerateHypothesis()
	if err != nil {
		return nil, utils.Error("failed to generate current hypothesis", err)
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

	return next_hypothesis, nil
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
			delt_i := a.conf.SBoxInv()[utils.XORToInt(a.m_org.Bytes()[i], k)]
			delt_i ^= a.conf.SBoxInv()[utils.XORToInt(m_f.Bytes()[i], k)]

			for j, delt := range d_mult {
				if delt_i == delt {
					HV[i][j] = utils.AppendByte(HV[i][j], byte(k))
				}
			}
		}
	}

	return a.collectValidHypotheses(HV), m_f, nil
}

func (a *Attack) Interact(message *big.Int, fault []byte) (*big.Int, os.Error) {
	m := make([]byte, len(message.Bytes())*2)
	hex.Encode(m, message.Bytes())
	m = utils.Pad(bytes.AddByte(m, '\n'), WORD_LENGTH)

	if err := a.cmd.WriteStdin(fault); err != nil {
		return nil, utils.Error("failed to write fault", err)
	}
	if err := a.cmd.WriteStdin(m); err != nil {
		return nil, utils.Error("failed to write ciphertext", err)
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
		return nil, utils.Error("failed to read message", err)
	}

	i, err := utils.BytesToInt(utils.TrimLeft(c))
	if err != nil {
		return nil, utils.Error("failed to convert message to int", err)
	}

	return i, err
}

func (a *Attack) collectValidHypotheses(HV [][][]byte) [][][]byte {
	hypotheses := make([][][]byte, 4)

	aRange := [][]byte{[]byte{0, 13, 10, 7}, []byte{4, 1, 14, 11}, []byte{8, 5, 2, 15}, []byte{12, 9, 6, 3}}

	for cnt, bytes := range aRange {
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

	return hypotheses
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
