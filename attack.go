package main

import (
	"big"
	"bufio"
	"exec"
	"fmt"
	"os"
	"syscall"
)

const (
	newline = 10
)

type Attack struct {
	cmd *exec.Cmd

	attackFile string
	conf       *Conf
}

type Conf struct {
	n      int
	values []*big.Int
	fields []string
}

func newError(err string) os.Error {
	return os.NewError(err)
}

func fatal(err os.Error) {
	fmt.Printf("%v\n", err.String())
	os.Exit(1)
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
	}

	reader := bufio.NewReader(f)
	for {
		b, err := reader.ReadBytes(byte(newline))
		if err != nil {
			break
		}

		// Get rid of trailing newline (10)
		d := make([]byte, len(b)-1)
		copy(d, b)

		conf.fields[conf.n] = string(d)

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

	return &Attack{attackFile: args[0], conf: conf}, nil
}

func main() {
	attack, err := NewAttack()
	if err != nil {
		fatal(err)
	}

	fmt.Printf("%v\n", attack)

	//cmd, err := exec.Run("/bin/echo", []string{"echo", "hello"}, nil, exec.Pipe, exec.Pipe, exec.Pipe)
	//cmd, err := exec.Run("./oaep/23305.D", []string{"23305.D"}, nil, exec.Pipe, exec.Pipe, exec.Pipe)
	//if err != nil {
	//	fmt.Printf("error running command: %v", err)
	//}

	//fmt.Printf("here\n")

	//go func() {
	//	for i := 0; i < 100000; i++ {
	//		buff := []byte{0, 0, 1}
	//		_, err = cmd.Stdin.Write(buff)
	//		if err != nil {
	//			//fmt.Printf("failed to write stdin file: %v\n", err)
	//		}
	//	}
	//}()

	////fmt.Printf("HERE")

	//go func() {
	//	for {
	//		buff := make([]byte, 1024)
	//		n, err := cmd.Stdout.Read(buff)
	//		if err != nil {
	//			//fmt.Printf("failed to write stdin file: %v\n", err)
	//		}
	//		if n > 0 {
	//			fmt.Printf("%s\n", string(buff[0]))
	//		}
	//	}
	//}()

	//go func() {
	//	for {
	//		buff := make([]byte, 1024)
	//		n, err := cmd.Stderr.Read(buff)
	//		if err != nil {
	//			//fmt.Printf("failed to write stdin file: %v\n", err)
	//		}
	//		if n > 0 {
	//			fmt.Printf("here2: %v\n", buff[0])
	//		}
	//	}
	//}()

	//fmt.Printf("%v\n", cmd.Pid)
	//fmt.Printf("%v\n", cmd.Stdin)
	//fmt.Printf("%v\n", cmd.Stdout)
	//fmt.Printf("%v\n", cmd.Stderr)

	//wait, err := cmd.Wait(0)
	//if err != nil {
	//	fmt.Printf("error waiting for command: %v", err)
	//}

	//fmt.Printf("Command complete\n")
	//fmt.Printf("%v\n", wait)
}
