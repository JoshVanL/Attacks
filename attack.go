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

	return nil
}

func (a *Attack) Read() ([]byte, os.Error) {
	b := make([]byte, 1024)

	if _, err := a.cmd.Stdout.Read(b); err != nil {
		return nil, utils.Error("failed to read stdout file", err)
	}

	return b, nil
}

func (a *Attack) Interact(c *big.Int) (res int, err os.Error) {
	m := []byte(utils.IntToHexBytes(c))

	if err := a.Write(a.conf.Bytes[2], m); err != nil {
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

	for code == C_LENGTH {
		f1.Mul(f1, two)
		m = a.conf.RSAf(f1)
		code, err = a.Interact(m)
		if err != nil {
			return nil, err
		}
	}

	return f1, nil
}

//func (a *Attack) WriteStdin() {
//	b := true
//	var buff []byte
//
//	for i := 0; i < 1000; i++ {
//		if b {
//			buff = a.conf.bytes[2]
//		} else {
//			buff = a.conf.bytes[3]
//			//tmp := make([]byte, len(a.conf.bytes[3])+1)
//			//tmp = a.conf.bytes[3]
//			//tmp[len(tmp)] = 0
//			//a.conf.bytes[3] = tmp
//		}
//
//		n, err := a.cmd.Stdin.Write(buff)
//		if err != nil {
//			fmt.Printf("failed to write stdin file: %v\n", err)
//		}
//		fmt.Printf("(%d)wrote:%s", n, string(buff))
//
//		b = !b
//		if b {
//			a.block <- 0
//			a.interactions++
//		}
//	}
//
//	close(a.stopCh)
//}
//
//func (a *Attack) ReadStdout() {
//	for {
//		select {
//		case <-a.stopCh:
//			return
//
//		default:
//			buff := make([]byte, 1024)
//
//			<-a.block
//			_, err := a.cmd.Stdout.Read(buff)
//			if err != nil {
//				fmt.Printf("failed to read stdout file: %v\n", err)
//			}
//			printResponse(int(buff[0]) - 48)
//		}
//	}
//}
//
//func (a *Attack) ReadStderr() {
//	for {
//		select {
//		case <-a.stopCh:
//			return
//
//		default:
//			buff := make([]byte, 1024)
//			n, err := a.cmd.Stderr.Read(buff)
//			if err != nil {
//				fmt.Printf("failed to read stderr file: %v\n", err)
//			}
//			if n > 0 {
//				fmt.Printf("Stderr: %v\n", buff[0])
//			}
//		}
//	}
//}

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
	_, err = a.findF1()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")

	//fmt.Printf("%d\n", len(a.conf.bytes[0]))
	//fmt.Printf("%d\n", len(a.conf.bytes[3]))
	//fmt.Printf("%v\n", a.conf.bytes[0])
	//fmt.Printf("%v\n", a.conf.bytes[3])

	//go a.WriteStdin()

	//go a.ReadStdout()

	//go a.ReadStderr()

	//fmt.Printf("%v\n", cmd.Pid)
	//fmt.Printf("%v\n", cmd.Stdin)
	//fmt.Printf("%v\n", cmd.Stdout)
	//fmt.Printf("%v\n", cmd.Stderr)

	//wait, err := cmd.Wait(0)
	//if err != nil {
	//	return newError(fmt.Sprintf("error waiting for command: %v", err))
	//}

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

	//fmt.Printf("%s\n", a.conf.K.String())
	//fmt.Printf("%s\n", a.conf.B.String())
	//fmt.Printf("%s\n", a.conf.N.String())
	//fmt.Printf("%s\n", utils.IntToHex(a.conf.N))
	//if err := attack.Run(); err != nil {
	//	fatal(err)
	//}
}
