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
	"runtime"
	"encoding/hex"
	"fmt"
	"os"
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

	hypotheses, m_f, err := a.GenerateHypothesis()
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

	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[0][i] = mul(2, i)
	}
	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[1][i] = mul(3, i)
	}
	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[2][i] = mul(6, i)
	}
	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[3][i] = mul(9, i)
	}
	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[4][i] = mul(11, i)
	}
	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[5][i] = mul(13, i)
	}
	for i := 0; i < KEY_RANGE; i++ {
		MULTAB[6][i] = mul(14, i)
	}

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)
	fmt.Printf("Target material: [%X]\n", d)
	fmt.Printf("Interactions: %d\n", a.interactions)

	k, err := a.AttackSingleFault(hypotheses, m_f)
	if err != nil {
		return utils.Error("error during single fault", err)
	}

	if k != nil {
		fmt.Printf("Key Found: [%X]\n", k)
	} else {
		fmt.Printf("Key not found.\n")
	}

	return nil
}

func (a *Attack) AttackSingleFault(hypotheses [][][]byte, m_f []byte) ([]byte, os.Error) {
	inputs := make([][]byte, len(hypotheses[2])*len(hypotheses[3]))

	for i1 := 0; i1 < len(hypotheses[0]); i1++ {
		start1 := time.Nanoseconds()
		for i2 := 0; i2 < len(hypotheses[1]); i2++ {
			i := 0
			for i3 := 0; i3 < len(hypotheses[2]); i3++ {
				for i4 := 0; i4 < len(hypotheses[3]); i4++ {
					inputs[i] = []byte{byte(i1), byte(i2), byte(i3), byte(i4)}
					i++
				}
			}

			wg := utils.NewWaitGroup(len(inputs))

			for _, i := range inputs {
				go func() {
					k := a.maths(i, a.m_org, m_f, hypotheses)
					if k != nil {
						fmt.Printf("Potential key found: %X\n", k)

						check, err := a.CheckKey(k)
						if err != nil {
							//return nil, utils.Error("error checking potential key", err)
							fmt.Printf("error checking potential key: %v\n", err)
							os.Exit(1)
						}

						if check {
							//return k, nil
							fmt.Printf("Key Found: [%X]\n", k)
							os.Exit(0)
						}
					}

					wg.Done()
				}()
			}

			runtime.Gosched()
			go wg.Wait()

		}

		fmt.Printf("Round %d / %d\n", i1+1, len(hypotheses[1]))
		fmt.Printf("Elapsed time: %.2fs\n", float((time.Nanoseconds()-start1))/1e9)
	}

	return nil, nil
}

func (a *Attack) GenerateHypothesis() (hypotheses [][][]byte, m_f []byte, err os.Error) {
	f := a.conf.BuildFault(8, 1, 0, 0, 0)

	m_f, err = a.Interact(a.m_org, f)
	if err != nil {
		return nil, nil, err
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

	return a.collectValidHypotheses(HV), m_f, nil
}

func (a *Attack) maths(input []byte, message []byte, m_f []byte, hypothesis [][][]byte) []byte {
	///

	i1 := input[0]
	i2 := input[1]
	i3 := input[2]
	i4 := input[3]

	k1 := hypothesis[0][i1][0]
	k14 := hypothesis[0][i1][1]
	k11 := hypothesis[0][i1][2]
	k8 := hypothesis[0][i1][3]

	k5 := hypothesis[1][i2][0]
	k2 := hypothesis[1][i2][1]
	k15 := hypothesis[1][i2][2]
	k12 := hypothesis[1][i2][3]

	k9 := hypothesis[2][i3][0]
	k6 := hypothesis[2][i3][1]
	k3 := hypothesis[2][i3][2]
	k16 := hypothesis[2][i3][3]

	k13 := hypothesis[3][i4][0]
	k10 := hypothesis[3][i4][1]
	k7 := hypothesis[3][i4][2]
	k4 := hypothesis[3][i4][3]

	k := []byte{0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16}

	inv_s := a.conf.SBoxInv()
	r_con := a.conf.RoundConstant()
	x := make([]byte, len(message)+1)
	xp := make([]byte, len(m_f)+1)
	copy(x[1:], message)
	copy(xp[1:], m_f)
	s := a.conf.SBox()

	aa := inv_s[MULTAB[6][inv_s[x[1]^k[1]]^k[1]^s[k[14]^k[10]]^r_con[10]]^
		MULTAB[4][inv_s[x[14]^k[14]]^k[2]^s[k[15]^k[11]]]^
		MULTAB[5][inv_s[x[11]^k[11]]^k[3]^s[k[16]^k[12]]]^
		MULTAB[3][inv_s[x[8]^k[8]]^k[4]^s[k[13]^k[9]]]] ^ inv_s[MULTAB[6][inv_s[xp[1]^k[1]]^k[1]^s[k[14]^k[10]]^r_con[10]]^
		MULTAB[4][inv_s[xp[14]^k[14]]^k[2]^s[k[15]^k[11]]]^
		MULTAB[5][inv_s[xp[11]^k[11]]^k[3]^s[k[16]^k[12]]]^
		MULTAB[3][inv_s[xp[8]^k[8]]^k[4]^s[k[13]^k[9]]]]

	b := inv_s[MULTAB[3][inv_s[x[13]^k[13]]^k[13]^k[9]]^
		MULTAB[6][inv_s[x[10]^k[10]]^k[10]^k[14]]^
		MULTAB[4][inv_s[x[7]^k[7]]^k[15]^k[11]]^
		MULTAB[5][inv_s[x[4]^k[4]]^k[16]^k[12]]] ^
		inv_s[MULTAB[3][inv_s[xp[13]^k[13]]^k[13]^k[9]]^
			MULTAB[6][inv_s[xp[10]^k[10]]^k[10]^k[14]]^
			MULTAB[4][inv_s[xp[7]^k[7]]^k[15]^k[11]]^
			MULTAB[5][inv_s[xp[4]^k[4]]^k[16]^k[12]]]

	if aa != byte(MULTAB[0][b]) {
		return nil
	}

	c := inv_s[MULTAB[5][inv_s[x[9]^k[9]]^k[9]^k[5]]^
		MULTAB[3][inv_s[x[6]^k[6]]^k[10]^k[6]]^
		MULTAB[6][inv_s[x[3]^k[3]]^k[11]^k[7]]^
		MULTAB[4][inv_s[x[16]^k[16]]^k[12]^k[8]]] ^
		inv_s[MULTAB[5][inv_s[xp[9]^k[9]]^k[9]^k[5]]^
			MULTAB[3][inv_s[xp[6]^k[6]]^k[10]^k[6]]^
			MULTAB[6][inv_s[xp[3]^k[3]]^k[11]^k[7]]^
			MULTAB[4][inv_s[xp[16]^k[16]]^k[12]^k[8]]]

	if b != c {
		return nil
	}

	d := inv_s[MULTAB[4][inv_s[x[5]^k[5]]^k[5]^k[1]]^
		MULTAB[5][inv_s[x[2]^k[2]]^k[6]^k[2]]^
		MULTAB[3][inv_s[x[15]^k[15]]^k[7]^k[3]]^
		MULTAB[6][inv_s[x[12]^k[12]]^k[8]^k[4]]] ^
		inv_s[MULTAB[4][inv_s[xp[5]^k[5]]^k[5]^k[1]]^
			MULTAB[5][inv_s[xp[2]^k[2]]^k[6]^k[2]]^
			MULTAB[3][inv_s[xp[15]^k[15]]^k[7]^k[3]]^
			MULTAB[6][inv_s[xp[12]^k[12]]^k[8]^k[4]]]

	if byte(MULTAB[1][c]) != d {
		return nil
	}

	if MULTAB[1][aa] == MULTAB[2][b] && MULTAB[2][b] == MULTAB[2][c] && MULTAB[2][c] == MULTAB[0][d] {
		return []byte{k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16}
	} else {
		return nil
	}

	return nil
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
	curr_hypothesis, _, err := a.GenerateHypothesis()
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

func mul(a, b int) int {
	result := 0
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			result ^= a
		}
		bit := a & 0x80
		a <<= 1
		if bit == 0x80 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return result % 256
}
