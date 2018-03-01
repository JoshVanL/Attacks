package main

import (
	"time"
	"bytes"
	"fmt"
	"encoding/hex"
	"crypto/sha1"
	"big"
	"os"

	"./oaep_c"
	"./utils"
	"./command"
)

const (
	SUCCESS = '0'
	ERROR1  = '1'
	ERROR2  = '2'

	WORD_LENGTH = 256
	BASE        = 16
)

type Attack struct {
	cmd  *command.Command
	conf *oaep_c.Conf

	interactions int
}

func NewAttack() (attack *Attack, err os.Error) {
	args, err := utils.ParseArguments()
	if err != nil {
		return nil, err
	}

	conf, err := oaep_c.NewConf(args[1])
	if err != nil {
		return nil, err
	}

	cmd, err := command.NewCommand(args[0])
	if err != nil {
		return nil, err
	}

	return &Attack{
		conf: conf,
		interactions: 0,
		cmd: cmd,
	},
		nil
}

func (a *Attack) Write(l, c []byte) os.Error {
	if err := a.cmd.WriteStdin(l); err != nil {
		return utils.Error("failed to write lable", err)
	}
	if err := a.cmd.WriteStdin(c); err != nil {
		return utils.Error("failed to write ciphertext ", err)
	}

	return nil
}

func (a *Attack) Read() ([]byte, os.Error) {
	b, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, utils.Error("failed to read stdout file", err)
	}

	return b, nil
}

func (a *Attack) Interact(c *big.Int) (res byte, err os.Error) {
	n := make([]byte, len(c.Bytes())*2)
	hex.Encode(n, c.Bytes())
	n = utils.Pad(bytes.AddByte(n, '\n'), WORD_LENGTH)

	if err := a.Write(a.conf.L, n); err != nil {
		return 0, err
	}

	b, err := a.Read()
	if err != nil {
		return 0, err
	}

	a.interactions++

	if b[0] > ERROR2 {
		utils.Fatal(utils.NewError(fmt.Sprintf("got bad error code from D: %s\n", string(b[0]))))
	}

	return b[0], nil
}

func (a *Attack) findF1() (*big.Int, os.Error) {
	f1 := big.NewInt(2)
	two := big.NewInt(2)
	m := a.conf.RSAf(f1)
	code, err := a.Interact(m)
	if err != nil {
		return nil, err
	}

	for code != ERROR1 {
		f1.Mul(f1, two)
		m = a.conf.RSAf(f1)
		code, err = a.Interact(m)
		if err != nil {
			return nil, err
		}
	}

	return f1, nil
}

func (a *Attack) findF2(f1 *big.Int) (*big.Int, os.Error) {
	f1_half := new(big.Int)
	f2 := new(big.Int)
	f1_half, _ = f1_half.Div(f1, big.NewInt(2))

	f2.Add(a.conf.N, a.conf.B)
	f2, _ = f2.Div(f2, a.conf.B)
	f2.Mul(f2, f1_half)

	m := a.conf.RSAf(f2)
	code, err := a.Interact(m)
	if err != nil {
		return nil, err
	}

	for code != ERROR2 {
		f2.Add(f2, f1_half)
		m := a.conf.RSAf(f2)

		code, err = a.Interact(m)
		if err != nil {
			return nil, err
		}
	}

	return f2, nil
}

func (a *Attack) findEM(f2 *big.Int) (*big.Int, os.Error) {
	m_max := new(big.Int)
	f_tmp := new(big.Int)
	tmp := new(big.Int)
	i := new(big.Int)
	two := big.NewInt(2)

	m_min := utils.CeilingDiv(a.conf.N, f2)

	m_max.Add(a.conf.N, a.conf.B)
	m_max, _ = m_max.Div(m_max, f2)

	f3 := big.NewInt(0)

	for m_min.Cmp(m_max) != 0 {

		if m_min.Cmp(m_max) > 0 {
			return nil, utils.NewError(fmt.Sprintf("m_min larger than m_max: %s : %s\n", m_min.String(), m_max.String()))
		}

		f_tmp.Mul(a.conf.B, two)
		tmp.Sub(m_max, m_min)
		f_tmp, _ = f_tmp.Div(f_tmp, tmp)

		i.Mul(f_tmp, m_min)
		i, _ = i.Div(i, a.conf.N)

		f3.Mul(i, a.conf.N)
		f3 = utils.CeilingDiv(f3, m_min)

		m := a.conf.RSAf(f3)

		code, err := a.Interact(m)
		if err != nil {
			return nil, err
		}

		switch code {

		case ERROR1:
			m_min.Mul(i, a.conf.N)
			m_min.Add(m_min, a.conf.B)
			m_min = utils.CeilingDiv(m_min, f3)

		case ERROR2:
			m_max.Mul(i, a.conf.N)
			m_max.Add(m_max, a.conf.B)
			m_max, _ = m_max.Div(m_max, f3)

		default:
			fmt.Printf("Received error code: %s\n", string(code))
			fmt.Printf("%s\n", m.String())
			os.Exit(1)
		}
	}

	return m_min, nil
}

func (a *Attack) checkMessage(m *big.Int) os.Error {
	m_c := new(big.Int)
	m_c.Exp(m, a.conf.E, a.conf.N)

	if m_c.Cmp(a.conf.C) != 0 {
		return utils.NewError("calculated message cipher and given cipertexts don't match.")
	}

	return nil
}

func (a *Attack) EME_OAEP_Decode(em *big.Int) ([]byte, os.Error) {
	hLen := int64(sha1.New().Size())
	m := em.Bytes()

	maskedSeed := m[0:hLen]
	maskedDB := m[hLen:len(m)]

	seedMask, err := a.conf.MGF1(maskedDB, hLen)
	if err != nil {
		return nil, utils.Error("error calculating seedMask", err)
	}
	seed := utils.XOR(maskedSeed, seedMask)

	dbMask, err := a.conf.MGF1(seed, int64(len(m))-hLen)
	if err != nil {
		return nil, utils.Error("error calculating dbMask", err)
	}
	DB := utils.XOR(maskedDB, dbMask)

	indexM := bytes.IndexByte(DB, 1)
	if indexM < int(hLen) {
		return nil, utils.NewError("failed to find 01 in DB string")
	}
	fmt.Printf("done.\n")

	// Check that pHash and pHash' are equal
	fmt.Printf("Checking label...")
	hash := sha1.New()
	l := new(big.Int)
	l.SetString(string(a.conf.L[0:len(a.conf.L)-1]), BASE)
	if _, err := hash.Write(l.Bytes()); err != nil {
		return nil, err
	}

	if !bytes.Equal(hash.Sum(), DB[0:hLen]) {
		return nil, utils.NewError("label and resulting hash are different")
	}
	fmt.Printf("done.\n")

	return DB[indexM+1:], nil
}

func (a *Attack) Run() os.Error {
	fmt.Printf("Executing Attack.\n")

	if err := a.cmd.Run(); err != nil {
		return utils.Error("failed to run attack command", err)
	}

	now := time.Nanoseconds()

	fmt.Printf("Finding F1...")
	f1, err := a.findF1()
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")
	fmt.Printf("F1: %s\n", f1.String())

	fmt.Printf("Finding F2...")
	f2, err := a.findF2(f1)
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")
	fmt.Printf("F2: %s\n", f2.String())

	fmt.Printf("Finding EM...")
	em, err := a.findEM(f2)
	if err != nil {
		return err
	}
	fmt.Printf("done.\n")

	if err := a.cmd.Kill(); err != nil {
		return err
	}

	fmt.Printf("Checking EM...")
	if err := a.checkMessage(em); err != nil {
		return err
	}
	fmt.Printf("done.\n")
	//fmt.Printf("EM: [%X]\n", em.Bytes())

	fmt.Printf("Decoding EM...")
	M, err := a.EME_OAEP_Decode(em)
	if err != nil {
		return utils.Error("decoding error", err)
	}

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	fmt.Printf("Target material: [%X]\n", M)
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
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
