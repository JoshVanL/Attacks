package main

import (
	"fmt"
	"big"
	"encoding/hex"
	"bytes"
	"os"

	"./utils"
	"./time_c"
	"./command"
	"./montgomery"
)

const (
	WORD_LENGTH = 256
)

type Attack struct {
	cmd  *command.Command
	conf *time_c.Conf

	interactions int

	samples      []*Sample
	mnt          *montgomery.Montgomery
	d            *big.Int
	test_message *big.Int
	c            *big.Int
}

type Sample struct {
	time    []byte
	message []byte
	mont    *big.Int
	curr    *big.Int
}

func NewAttack() (attack *Attack, err os.Error) {
	args, err := utils.ParseArguments()
	if err != nil {
		return nil, err
	}

	conf, err := time_c.NewConf(args[1])
	if err != nil {
		return nil, err
	}

	cmd, err := command.NewCommand(args[0])
	if err != nil {
		return nil, err
	}

	return &Attack{
		conf: conf,
		cmd: cmd,
		interactions: 0,
		mnt: montgomery.NewMontgomery(conf.N),
		d: big.NewInt(1),
		test_message: new(big.Int),
		c: new(big.Int),
	},
		nil
}


func (a *Attack) Write(c []byte) os.Error {
	if err := a.cmd.WriteStdin(c); err != nil {
		return utils.Error("failed to write ciphertext ", err)
	}

	return nil
}

func (a *Attack) Read() (m []byte, t []byte, err os.Error) {
	b, err := a.cmd.ReadStdout()
	if err != nil {
		return nil, nil, utils.Error("failed to read stdout file", err)
	}

	split := bytes.Split(b, []byte{'\n'}, 3)
	if len(split) != 3 {
		return nil, nil, utils.NewError(fmt.Sprintf("got unexpected number of splits from read. exp=3 got=%d\n", len(split)))
	}

	return split[0], split[1], nil
}

func (a *Attack) Interact(c *big.Int) (m []byte, t []byte, err os.Error) {
	n := make([]byte, len(c.Bytes())*2)
	hex.Encode(n, c.Bytes())
	n = utils.Pad(bytes.AddByte(n, '\n'), WORD_LENGTH)
	//fmt.Printf(">%s>", n)

	if err := a.Write(n); err != nil {
		return nil, nil, err
	}

	m, t, err = a.Read()
	if err != nil {
		return nil, nil, err
	}

	a.interactions++

	return m, t, nil
}

func (a *Attack) generate_samples() os.Error {
	a.samples = make([]*Sample, 1300)
	for i := 0; i < 1300; i++ {
		c := utils.RandInt(a.conf.N)
		mnt, _ := a.mnt.Mul(c, a.mnt.Ro2)
		curr := a.mnt.Exp(mnt, a.d)
		time, message, err := a.Interact(c)
		if err != nil {
			return utils.Error("error interacting with program", err)
		}

		//fmt.Printf("message: %s\n", message)
		//fmt.Printf("time: %s\n", time)

		a.c = c

		a.samples[i] = &Sample{
			time: time,
			message: message,
			mont: mnt,
			curr: curr,
		}

		a.test_message.SetBytes(message)
	}

	return nil
}

func (a *Attack) find_key() os.Error {
	//for new(big.Int).Exp(a.c, a.d, a.conf.N).Cmp(a.test_message) != 0 {
	n := 1
	for n < 64 {
		var c_0 []*big.Int
		var c_1 []*big.Int
		var bit0_red [][]byte
		var bit0_nored [][]byte
		var bit1_red [][]byte
		var bit1_nored [][]byte

		fmt.Printf("\rGuessing bit [%d]...", n)
		for _, s := range a.samples {
			ci_0, _ := a.mnt.Mul(s.curr, s.curr)
			c_0 = utils.AppendBigInt(c_0, ci_0)
			ci_0, red0 := a.mnt.Mul(ci_0, ci_0)

			if red0 {
				bit0_red = utils.AppendBytes(bit0_red, s.time)
			} else {
				bit0_nored = utils.AppendBytes(bit0_nored, s.time)
			}

			ci_1, _ := a.mnt.Mul(s.curr, s.curr)
			ci_1, _ = a.mnt.Mul(ci_1, s.mont)
			c_1 = utils.AppendBigInt(c_1, ci_1)
			ci_1, red1 := a.mnt.Mul(ci_1, ci_1)
			if red1 {
				bit1_red = utils.AppendBytes(bit1_red, s.time)
			} else {
				bit1_nored = utils.AppendBytes(bit1_nored, s.time)
			}
		}

		//for _, b := range bit0_red {
		//	fmt.Printf("%s\n", b)
		//}
		//for _, r := range bit0_red {
		//	fmt.Printf("bit0_red: %s\n", r)
		//}

		mean_bit0_red, err := utils.SumBytes(bit0_red)
		if err != nil {
			return err
		}
		//fmt.Printf("%s\n", mean_bit0_red)
		//fmt.Printf("time: %s\n", a.samples[0].time)
		//os.Exit(1)
		//fmt.Printf("sum1: %s\n", mean_bit0_red)
		//fmt.Printf("sum1: %s\n", mean_bit0_red)
		mean_bit0_red, _ = mean_bit0_red.Div(mean_bit0_red, big.NewInt(int64(len(bit0_red))))
		//fmt.Printf("len: %d\n", len(bit0_red))
		mean_bit0_nored, err := utils.SumBytes(bit0_nored)
		if err != nil {
			return err
		}
		mean_bit0_nored, _ = mean_bit0_nored.Div(mean_bit0_nored, big.NewInt(int64(len(bit0_nored))))

		mean_bit1_red, err := utils.SumBytes(bit1_red)
		if err != nil {
			return err
		}
		mean_bit1_red, _ = mean_bit1_red.Div(mean_bit1_red, big.NewInt(int64(len(bit1_red))))
		mean_bit1_nored, err := utils.SumBytes(bit1_nored)
		if err != nil {
			return err
		}
		mean_bit1_nored, _ = mean_bit1_nored.Div(mean_bit1_nored, big.NewInt(int64(len(bit1_nored))))

		//fmt.Printf("sum1: %s\n", mean_bit0_red)
		//fmt.Printf("sum2: %s\n", mean_bit1_red)

		diff_0 := new(big.Int).Sub(mean_bit0_red, mean_bit0_nored)
		diff_1 := new(big.Int).Sub(mean_bit1_red, mean_bit1_nored)

		if diff_0.Cmp(diff_1) > 0 {
			a.d.Mul(a.d, big.NewInt(2))
			for i := range a.samples {
				a.samples[i].curr = c_0[i]
			}
			n += 1
		} else if diff_1.Cmp(diff_0) > 0 {
			a.d.Mul(a.d, big.NewInt(2))
			a.d.Add(a.d, big.NewInt(1))
			for i := range a.samples {
				a.samples[i].curr = c_1[i]
			}
			n += 1
		} else {
			panic("cant distinguish!")
		}

		if new(big.Int).Exp(a.c, new(big.Int).Mul(a.d, big.NewInt(2)), a.conf.N).Cmp(a.test_message) == 0 {
			a.d.Mul(a.d, big.NewInt(2))
			break
		} else if new(big.Int).Exp(a.c, new(big.Int).Add(new(big.Int).Mul(a.d, big.NewInt(2)), big.NewInt(1)), a.conf.N).Cmp(a.test_message) == 0 {
			a.d.Mul(a.d, big.NewInt(2))
			a.d.Add(a.d, big.NewInt(1))
			break
		}
	}
	//}

	return nil
}

func (a *Attack) Run() os.Error {
	if err := a.cmd.Run(); err != nil {
		return err
	}

	fmt.Printf("Generating samples...")
	if err := a.generate_samples(); err != nil {
		return utils.Error("failed to generate samples", err)
	}
	fmt.Printf("done.\n")

	fmt.Printf("Finding key...\n")
	if err := a.find_key(); err != nil {
		return utils.Error("error finding key", err)
	}
	fmt.Printf("done.\n")

	fmt.Printf("Key: [%X]\n", a.d.Bytes())

	return nil
}

func main() {
	fmt.Printf("Initalising attack...")
	a, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")

	if err := a.Run(); err != nil {
		utils.Fatal(err)
	}
}
