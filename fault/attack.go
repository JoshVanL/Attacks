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
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"time"

	"./command"
	"./fault_c"
	"./utils"
)

const (
	WORD_LENGTH = 16
	KEY_RANGE   = 256
)

var MULTAB [7][KEY_RANGE]int

type Attack struct {
	cmd *command.Command

	conf *fault_c.Conf

	c_org []byte
	m_org []byte

	table [][]byte

	interactions int
}

func main() {
	fmt.Printf("Initialising attack...")
	a, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")

	runtime.GOMAXPROCS(2)

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
		table: BuildTable(),
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

	fmt.Printf("Generating Initial Cipher...")
	m := utils.RandInt(2, 128).Bytes()
	c, err := a.Interact(m, []byte{'\n'})
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")

	a.c_org = c
	a.m_org = m

	fmt.Printf("Attacking Multi Fault...")
	key, err := a.MultiFaultAttack(c)
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")

	fmt.Printf("Inverseing Key...")
	d := a.InverseKey(key)
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

func (a *Attack) MultiFaultAttack(c []byte) ([]byte, os.Error) {
	f := a.conf.BuildFault(8, 1, 0, 0, 0)

	c2, err := a.Interact(a.m_org, f)
	if err != nil {
		return nil, err
	}

	c3, err := a.Interact(a.m_org, f)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n")

	key := make([]byte, WORD_LENGTH)

	factors := [][]int{
		[]int{2, 3, 1, 1},
		[]int{1, 1, 2, 3},
		[]int{2, 3, 1, 1},
		[]int{1, 1, 2, 3},
	}

	for i, indexes := range [][]int{
		[]int{0, 7, 10, 13},
		[]int{1, 4, 11, 14},
		[]int{2, 5, 8, 15},
		[]int{3, 6, 9, 12},
	} {

		hs1 := a.gatherHypotheses(c, c2, factors[i], indexes)
		hs2 := a.gatherHypotheses(c, c3, factors[i], indexes)

	LOOP:
		for _, h1 := range hs1 {
			for _, h2 := range hs2 {
				if a.sameBytes(h1, h2) {
					for j := range h1 {
						key[indexes[j]] = h1[j]
					}
					break LOOP
				}
			}
		}
	}

	return key, nil
}

func (a *Attack) gatherHypotheses(x, xp []byte, factor, index []int) [][]byte {
	var hypotheses [][]byte

	for i := 0; i < KEY_RANGE; i++ {
		var ks [4][]byte

		for j := 0; j < KEY_RANGE; j++ {
			for k := 0; k < 4; k++ {
				if a.table[factor[k]][i] == a.conf.SBoxInv()[x[index[k]]^byte(j)]^a.conf.SBoxInv()[xp[index[k]]^byte(j)] {
					ks[k] = utils.AppendByte(ks[k], byte(j))
				}
			}
		}

		for _, k1 := range ks[0] {
			for _, k2 := range ks[1] {
				for _, k3 := range ks[2] {
					for _, k4 := range ks[3] {
						hypotheses = utils.AppendByte2(hypotheses, []byte{k1, k2, k3, k4})
					}
				}
			}
		}
	}

	return hypotheses
}

func (a *Attack) InverseKey(ik []byte) []byte {
	for i := 10; i > 0; i-- {
		tmp := make([]byte, 12)
		for j := 0; j < 12; j++ {
			tmp[j] = ik[j] ^ ik[j+4]
		}
		copy(ik[4:len(ik)], tmp)

		ik[1] = a.conf.SBox()[ik[14]] ^ ik[1]
		ik[2] = a.conf.SBox()[ik[15]] ^ ik[2]
		ik[3] = a.conf.SBox()[ik[12]] ^ ik[3]

		ik[0] = a.conf.SBox()[ik[13]] ^ ik[0] ^ a.conf.RoundConstant()[i]
	}

	return ik
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

func BuildTable() [][]byte {
	table := make([][]byte, 4)

	wg := utils.NewWaitGroup(3)

	for i := 1; i < 4; i++ {

		go func(i int) {
			table[i] = make([]byte, KEY_RANGE)
			for j := 0; j < KEY_RANGE; j++ {
				table[i][j] = gf28(byte(i), byte(j))
			}
			wg.Done()
		}(i)
	}

	runtime.Gosched()
	go wg.Wait()

	return table
}

func gf28(a, b byte) byte {
	var t byte
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			t ^= a
		}
		tmp := a & 0x80
		a <<= 1
		if tmp == 0x80 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return t & 0xFF
}
