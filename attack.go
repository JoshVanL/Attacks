package main

import (
	"big"
	"bufio"
	"exec"
	"fmt"
	"os"
	"syscall"

	"./oaep"
)

const (
	newline = 10

	SUCCESS      = 0
	ERROR1       = 1
	ERROR2       = 2
	P_OUTOFRANGE = 3
	C_OUTOFRANGE = 4
	M_LENGTH     = 5
	C_LENGTH     = 6
	CH_LENGTH    = 7
)

type Attack struct {
	cmd *exec.Cmd

	attackFile string
	conf       *Conf

	block        chan int
	interactions int
	stopCh       chan interface{}
}

type Conf struct {
	n      int
	values []*big.Int
	fields []string
	bytes  [][]byte
}

func newError(err string) os.Error {
	return os.NewError(err)
}

func fatal(err os.Error) {
	fmt.Printf("%v\n", err.String())
	os.Exit(1)
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

func parseArguments() ([]string, os.Error) {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		return nil, newError(fmt.Sprintf("expected 1 or 2 argmuents, got=%d", len(os.Args)-1))
	}

	return os.Args[1:], nil
}

func appendString(slice []string, elem string) []string {
	if len(slice) < cap(slice) {
		slice = slice[0 : len(slice)+1]
		slice[len(slice)-1] = elem
		return slice
	}

	fresh := make([]string, len(slice)+1, cap(slice)*2+1)
	copy(fresh, slice)
	fresh[len(slice)] = elem
	return fresh
}

func readConf(filename string) (conf *Conf, err os.Error) {
	f, err := os.Open(filename, syscall.O_RDONLY, 666)
	if err != nil {
		return nil, newError(fmt.Sprintf("failed to read conf file: %v", err))
	}

	conf = &Conf{
		n:      0,
		values: make([]*big.Int, 5),
		fields: make([]string, 5),
		bytes:  make([][]byte, 5),
	}

	reader := bufio.NewReader(f)
	for {
		b, err := reader.ReadBytes(byte(newline))
		if err != nil {
			break
		}

		conf.bytes[conf.n] = b
		conf.fields[conf.n] = string(b)

		// Get rid of trailing newline (10)
		d := make([]byte, len(b)-1)
		copy(d, b)

		conf.values[conf.n] = new(big.Int)
		_, ok := conf.values[conf.n].SetString(string(d), 16)
		if !ok {
			return nil, newError("error when converting conf values to hex")
		}

		//fmt.Printf("%s\n", conf.values[conf.n].String())
		//fmt.Printf("%s\n", conf.fields[conf.n])

		conf.n++
	}

	return conf, nil
}

func NewAttack() (attack *Attack, err os.Error) {
	args, err := parseArguments()
	if err != nil {
		return nil, err
	}

	var conf *Conf
	if len(args) > 1 {
		conf, err = readConf(args[1])
		if err != nil {
			return nil, err
		}
	}

	return &Attack{
		attackFile: args[0],
		conf:       conf,
		block:      make(chan int),
		stopCh:     make(chan interface{}),
	}, nil
}

func (a *Attack) WriteStdin() {
	b := true
	var buff []byte

	for i := 0; i < 1000; i++ {
		if b {
			buff = a.conf.bytes[2]
		} else {
			buff = a.conf.bytes[3]
			//tmp := make([]byte, len(a.conf.bytes[3])+1)
			//tmp = a.conf.bytes[3]
			//tmp[len(tmp)] = 0
			//a.conf.bytes[3] = tmp
		}

		n, err := a.cmd.Stdin.Write(buff)
		if err != nil {
			fmt.Printf("failed to write stdin file: %v\n", err)
		}
		fmt.Printf("(%d)wrote:%s", n, string(buff))

		b = !b
		if b {
			a.block <- 0
			a.interactions++
		}
	}

	close(a.stopCh)
}

func (a *Attack) ReadStdout() {
	for {
		select {
		case <-a.stopCh:
			return

		default:
			buff := make([]byte, 1024)

			<-a.block
			_, err := a.cmd.Stdout.Read(buff)
			if err != nil {
				fmt.Printf("failed to read stdout file: %v\n", err)
			}
			printResponse(int(buff[0]) - 48)
		}
	}
}

func (a *Attack) ReadStderr() {
	for {
		select {
		case <-a.stopCh:
			return

		default:
			buff := make([]byte, 1024)
			n, err := a.cmd.Stderr.Read(buff)
			if err != nil {
				fmt.Printf("failed to read stderr file: %v\n", err)
			}
			if n > 0 {
				fmt.Printf("Stderr: %v\n", buff[0])
			}
		}
	}
}

func (a *Attack) Run() os.Error {
	if _, err := exec.LookPath(a.attackFile); err != nil {
		return newError(fmt.Sprintf("error looking up binary file '%s': %v", a.attackFile, err))
	}

	cmd, err := exec.Run(a.attackFile, []string{}, nil, exec.Pipe, exec.Pipe, exec.Pipe)
	if err != nil {
		return newError(fmt.Sprintf("error running command: %v", err))
	}
	a.cmd = cmd

	fmt.Printf("Begining attack...\n")

	//fmt.Printf("%d\n", len(a.conf.bytes[0]))
	//fmt.Printf("%d\n", len(a.conf.bytes[3]))
	//fmt.Printf("%v\n", a.conf.bytes[0])
	//fmt.Printf("%v\n", a.conf.bytes[3])

	go a.WriteStdin()

	go a.ReadStdout()

	go a.ReadStderr()

	//fmt.Printf("%v\n", cmd.Pid)
	//fmt.Printf("%v\n", cmd.Stdin)
	//fmt.Printf("%v\n", cmd.Stdout)
	//fmt.Printf("%v\n", cmd.Stderr)

	//wait, err := cmd.Wait(0)
	//if err != nil {
	//	return newError(fmt.Sprintf("error waiting for command: %v", err))
	//}

	<-a.stopCh
	fmt.Printf("Attack complete.\n")
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func main() {
	oaep.Foo()

	fmt.Printf("Initalising attack...\n")
	attack, err := NewAttack()
	if err != nil {
		fatal(err)
	}

	if err := attack.Run(); err != nil {
		fatal(err)
	}
}
