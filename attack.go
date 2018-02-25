package main

import (
	"exec"
	"fmt"
	"big"
	"os"

	"./oaep"
	"./utils"
)

const (
	SUCCESS      = '0'
	ERROR1       = '1'
	ERROR2       = '2'
	P_OUTOFRANGE = '3'
	C_OUTOFRANGE = '4'
	M_LENGTH     = '5'
	C_LENGTH     = '6'
	CH_LENGTH    = '7'
)

type Attack struct {
	cmd *exec.Cmd

	attackFile string
	conf       *oaep.Conf

	block        chan int
	interactions int
	stopCh       chan interface{}
}

func printResponse(e int) {
	var str string

	switch e {
	case SUCCESS:
		str = "SUCCESS(0)"
	case ERROR1:
		str = "ERROR1(1)"
	case ERROR2:
		str = "ERROR2(2)"
	case P_OUTOFRANGE:
		str = "P_OUTOFRANGE(3)"
	case C_OUTOFRANGE:
		str = "C_OUTOFRANGE(4)"
	case M_LENGTH:
		str = "M_LENGTH(5)"
	case C_LENGTH:
		str = "C_LENGTH(6)"
	case CH_LENGTH:
		str = "CH_LENGTH(7)"
	default:
		str = fmt.Sprintf("OTHER(%d)", e)
	}

	fmt.Printf("Response: %s\n", str)
}

func NewAttack() (attack *Attack, err os.Error) {
	args, err := utils.ParseArguments()
	if err != nil {
		return nil, err
	}

	conf, err := oaep.NewConf(args[1])
	if err != nil {
		return nil, err
	}

	return &Attack{
		attackFile: args[0],
		conf: conf,
		block: make(chan int),
		stopCh: make(chan interface{}),
		interactions: 0,
	},
		nil
}

func (a *Attack) Write(l, c []byte) os.Error {
	if _, err := a.cmd.Stdin.Write(l); err != nil {
		return utils.Error("failed to write lable to Stdin", err)
	}
	if _, err := a.cmd.Stdin.Write(c); err != nil {
		return utils.Error("failed to write ciphertext to Stdin", err)
	}

	//fmt.Printf("%s\n", string(l))
	//fmt.Printf("%s\n", string(c))

	return nil
}

func (a *Attack) Read() ([]byte, os.Error) {
	b := make([]byte, 10)

	if _, err := a.cmd.Stdout.Read(b); err != nil {
		return nil, utils.Error("failed to read stdout file", err)
	}

	return b, nil
}

func (a *Attack) Interact(c *big.Int) (res int, err os.Error) {
	m := []byte(utils.IntToOctBytes(c))
	m = utils.PadBytes(m, 256)
	//fmt.Printf("\n%s\n", string(m))
	//os.Exit(1)

	l := utils.PadBytes(a.conf.Bytes[2], 256)

	if err := a.Write(l, m); err != nil {
		return -1, err
	}

	b, err := a.Read()
	if err != nil {
		return -1, err
	}

	a.interactions++

	return int(b[0]), nil
}

func (a *Attack) findF1() (*big.Int, os.Error) {
	f1 := big.NewInt(2)
	two := big.NewInt(2)
	m := a.conf.RSAf(f1)
	code, err := a.Interact(m)
	if err != nil {
		return nil, err
	}

	for code != C_LENGTH {
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
		//fmt.Printf("%s\n", f2.String())
		//os.Exit(1)
		code, err = a.Interact(m)
		if err != nil {
			return nil, err
		}
		//fmt.Printf("%s\n", string(code))
		//if f2.Cmp(big.NewInt(223)) == 0 {
		//	os.Exit(1)
		//}
	}

	return f2, nil
}

func (a *Attack) findMesage(f2 *big.Int) (*big.Int, os.Error) {
	m_min := new(big.Int)
	m_max := new(big.Int)
	f_tmp := new(big.Int)
	tmp := new(big.Int)
	in := new(big.Int)

	m_min.Add(a.conf.N, f2)
	m_min.Sub(m_min, big.NewInt(1))
	m_min, _ = m_min.Div(m_min, f2)

	m_max.Add(a.conf.N, a.conf.B)
	m_max, _ = m_max.Div(m_max, f2)

	f3 := big.NewInt(0)

	for m_min.Cmp(m_max) != 0 {
		f_tmp.Mul(a.conf.B, big.NewInt(2))
		tmp.Sub(m_max, m_min)
		f_tmp, _ = f_tmp.Div(f_tmp, tmp)

		in.Mul(f_tmp, m_min)
		in, _ = in.Div(in, a.conf.N)

		f3.Mul(in, a.conf.N)
		f3.Add(f3, m_min)
		f3.Sub(f3, big.NewInt(1))
		f3, _ = f3.Div(f3, m_min)

		m := a.conf.RSAf(f3)
		code, err := a.Interact(m)
		if err != nil {
			return nil, err
		}

		switch code {

		case ERROR1:
			m_min.Mul(in, a.conf.N)
			m_min.Add(m_min, a.conf.B)
			m_min.Add(m_min, f3)
			m_min.Sub(m_min, big.NewInt(1))
			m_min, _ = m_min.Div(m_min, f3)

		case ERROR2:
			m_max.Mul(in, a.conf.N)
			m_max.Add(m_max, a.conf.B)
			m_max, _ = m_max.Div(m_max, f3)

		default:
			if m_min.Cmp(m_max) > 0 {
				fmt.Printf("m_min larger than m_max\n")
				fmt.Printf("%s\n%s\n", m_min.String(), m_max.String())
			} else {
				fmt.Printf("Received error code: %s\n", string(code))
			}
			os.Exit(1)
		}
	}

	m_c := new(big.Int)
	m_c.Exp(m_min, a.conf.E, a.conf.N)

	if m_c.Cmp(a.conf.C) != 0 {
		fmt.Printf("Message cipher and given cipertexts don't match.\n")
		fmt.Printf("%s\n%s\n", m_c.String(), a.conf.C.String())
		os.Exit(1)
	}

	fmt.Printf("Message cipher match!\n")

	return m_min, nil
}


func (a *Attack) Run() os.Error {
	if _, err := exec.LookPath(a.attackFile); err != nil {
		return utils.Error(fmt.Sprintf("error looking up binary file '%s'", a.attackFile), err)
	}

	cmd, err := exec.Run(a.attackFile, []string{}, nil, exec.Pipe, exec.Pipe, exec.Pipe)
	if err != nil {
		return utils.Error("error running command", err)
	}
	a.cmd = cmd

	fmt.Printf("Begining attack...\n")

	fmt.Printf("Finding f1...")
	f1, err := a.findF1()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")
	fmt.Printf("F1: %s\n", f1.String())

	fmt.Printf("Finding f2...")
	f2, err := a.findF2(f1)
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")
	fmt.Printf("F2: %s\n", f2.String())

	fmt.Printf("Finding message...")
	message, err := a.findMesage(f2)
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")
	fmt.Printf("Message: %s\n", message.String())

	fmt.Printf("Attack complete.\n")
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func main() {
	fmt.Printf("Initalising attack...\n")
	a, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}

	if err := a.Run(); err != nil {
		utils.Fatal(err)
	}
}
