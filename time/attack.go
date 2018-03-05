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

	samples *Samples
	mnt     *montgomery.Montgomery
	//d            *big.Int
	test_message *big.Int
	c            *big.Int
}

type Samples struct {
	xList    []*big.Int
	tList    []*big.Int
	cList    []*big.Int
	timeList []*big.Int
	messages []*big.Int
	//time    []byte
	//message []byte
	//mont    *big.Int
	//curr    *big.Int
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
		//d: big.NewInt(1),
		//test_message: new(big.Int),
		//c: new(big.Int),
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

func (a *Attack) Interact(c *big.Int) (m *big.Int, t *big.Int, err os.Error) {
	n := make([]byte, len(c.Bytes())*2)
	hex.Encode(n, c.Bytes())
	n = utils.Pad(bytes.AddByte(n, '\n'), WORD_LENGTH)
	//fmt.Printf(">%s>", n)

	if err := a.Write(n); err != nil {
		return nil, nil, err
	}

	tb, mb, err := a.Read()
	if err != nil {
		return nil, nil, err
	}

	m, err = utils.BytesToInt(mb)
	if err != nil {
		return nil, nil, utils.Error("failed to convert message bytes", err)
	}

	t, err = utils.BytesToInt(tb)
	if err != nil {
		return nil, nil, utils.Error("failed to convert time bytes", err)
	}

	a.interactions++

	return m, t, nil
}

func (a *Attack) generate_samples() os.Error {
	//a.samples = make([]*Sample, 1300)
	samples := new(Samples)

	t, _ := a.mnt.Mul(big.NewInt(1), a.mnt.Ro2)

	for i := 0; i < 5000; i++ {
		c := utils.RandInt(16, 128)
		//fmt.Printf(">%s\n", c)
		test_message, tt, err := a.Interact(c)
		if err != nil {
			return utils.Error("error interacting for samples", err)
		}
		samples.cList = utils.AppendBigInt(samples.cList, c)
		//fmt.Printf("t>%s\n", t)
		samples.timeList = utils.AppendBigInt(samples.timeList, tt)
		//fmt.Printf("t>%s\n", t)
		xHat, _ := a.mnt.Mul(c, a.mnt.Ro2)
		tTemp, _ := a.mnt.Mul(t, t)
		tTemp, _ = a.mnt.Mul(tTemp, xHat)
		samples.xList = utils.AppendBigInt(samples.xList, xHat)
		samples.tList = utils.AppendBigInt(samples.tList, tTemp)
		a.c = c
		a.test_message = test_message
	}

	//for i := 0; i < 1300; i++ {
	//	fmt.Printf("t>%s\n", samples.timeList[i])
	//}

	//for i := 0; i < 1300; i++ {
	//	c := utils.RandInt(a.conf.N)
	//	mnt, _ := a.mnt.Mul(c, a.mnt.Ro2)
	//	curr := a.mnt.Exp(mnt, a.d)
	//	time, message, err := a.Interact(c)
	//	if err != nil {
	//		return utils.Error("error interacting with program", err)
	//	}

	//	//fmt.Printf("message: %s\n", message)
	//	//fmt.Printf("time: %s\n", time)

	//	a.c = c

	//	a.samples[i] = &Sample{
	//		time: time,
	//		message: message,
	//		mont: mnt,
	//		curr: curr,
	//	}

	//	a.test_message.SetBytes(message)
	//}

	a.samples = samples

	return nil
}

func (a *Attack) find_key() os.Error {

	found := false
	K := "1"
	kSize := 1
	var greater *big.Int
	test_message := big.NewInt(2314234)
	test_cipher := new(big.Int).Exp(test_message, a.conf.E, a.conf.N)
	//foo := a.mnt.Exp(test_message, a.conf.E)

	for !found {
		kSize++
		var b1 []*big.Int
		var b2 []*big.Int
		var b3 []*big.Int
		var b4 []*big.Int
		var tList1 []*big.Int
		var tList0 []*big.Int

		for i := 0; i < 5000; i++ {
			tt := a.samples.timeList[i]
			xHat := a.samples.xList[i]
			t := a.samples.tList[i]

			tTemp, _ := a.mnt.Mul(t, t)
			t1, _ := a.mnt.Mul(tTemp, xHat)
			tList1 = utils.AppendBigInt(tList1, t1)
			_, red1 := a.mnt.Mul(t1, t1)

			tList0 = utils.AppendBigInt(tList0, tTemp)
			_, red0 := a.mnt.Mul(tTemp, tTemp)

			if red1 {
				b1 = utils.AppendBigInt(b1, tt)
			} else {
				b2 = utils.AppendBigInt(b2, tt)
			}
			if red0 {
				b3 = utils.AppendBigInt(b3, tt)
			} else {
				b4 = utils.AppendBigInt(b4, tt)
			}
		}
		chance1 := new(big.Int).Sub(average(b1), average(b2))
		chance0 := new(big.Int).Sub(average(b3), average(b4))

		if chance0.Cmp(chance1) > 0 {
			fmt.Printf("Difference was: %s\n", chance0)
			K = fmt.Sprintf("%s0", K)
			a.samples.tList = tList0
			greater = chance0
		} else {
			fmt.Printf("Difference was: %s\n", chance1)
			K = fmt.Sprintf("%s1", K)
			a.samples.tList = tList1
			greater = chance1
		}
		fmt.Printf("K = %s\n", K)

		kMaybe1 := utils.BinaryStringToInt(fmt.Sprintf("%s1", K))
		fmt.Printf("kMaybe1>%s\n", kMaybe1)
		//bla := a.mnt.Exp(a.c, kMaybe1)
		//bla = a.mnt.Red(bla)
		////bla := a.mnt.Exp(foo, kMaybe1)
		////bla = a.mnt.Red(bla)
		//fmt.Printf("m>%s\n", a.test_message)
		//fmt.Printf("bla>%s\n", bla)
		//if a.mnt.Exp(foo, kMaybe1).Cmp(test_message) == 0 {
		//if bla.Cmp(a.test_message) == 0 {
		if new(big.Int).Exp(test_cipher, kMaybe1, a.conf.N).Cmp(test_message) == 0 {
			fmt.Printf("key 1 here\n")
			os.Exit(1)
		}

		kMaybe0 := utils.BinaryStringToInt(fmt.Sprintf("%s0", K))
		fmt.Printf("kMaybe0>%s\n", kMaybe0)
		//bla = a.mnt.Exp(a.c, kMaybe0)
		//bla = a.mnt.Red(bla)
		////fmt.Printf("foo>%s\n", foo)
		//fmt.Printf("bla>%s\n", bla)
		//if a.mnt.Exp(foo, kMaybe0).Cmp(test_message) == 0 {
		if new(big.Int).Exp(test_cipher, kMaybe0, a.conf.N).Cmp(test_message) == 0 {
			fmt.Printf("key 0 here\n")
			os.Exit(1)
		}

		if greater.Cmp(big.NewInt(2)) < 0 {
			panic("greater is too small!")
		}

		//92319c502a2f137
	}

	return nil
}

func average(zs []*big.Int) *big.Int {
	if len(zs) == 0 {
		return big.NewInt(0)
	}

	z := new(big.Int)
	for _, n := range zs {
		z.Add(z, n)
	}

	z, _ = z.Div(z, big.NewInt(int64(len(zs))))

	return z
}

//func (a *Attack) find_key() os.Error {
//	//for new(big.Int).Exp(a.c, a.d, a.conf.N).Cmp(a.test_message) != 0 {
//	n := 1
//	for n < 64 {
//		var c_0 []*big.Int
//		var c_1 []*big.Int
//		var bit0_red [][]byte
//		var bit0_nored [][]byte
//		var bit1_red [][]byte
//		var bit1_nored [][]byte
//
//		fmt.Printf("\rGuessing bit [%d]...", n)
//		for _, s := range a.samples {
//			ci_0, _ := a.mnt.Mul(s.curr, s.curr)
//			c_0 = utils.AppendBigInt(c_0, ci_0)
//			ci_0, red0 := a.mnt.Mul(ci_0, ci_0)
//
//			if red0 {
//				bit0_red = utils.AppendBytes(bit0_red, s.time)
//			} else {
//				bit0_nored = utils.AppendBytes(bit0_nored, s.time)
//			}
//
//			ci_1, _ := a.mnt.Mul(s.curr, s.curr)
//			ci_1, _ = a.mnt.Mul(ci_1, s.mont)
//			c_1 = utils.AppendBigInt(c_1, ci_1)
//			ci_1, red1 := a.mnt.Mul(ci_1, ci_1)
//			if red1 {
//				bit1_red = utils.AppendBytes(bit1_red, s.time)
//			} else {
//				bit1_nored = utils.AppendBytes(bit1_nored, s.time)
//			}
//		}
//
//		//for _, b := range bit0_red {
//		//	fmt.Printf("%s\n", b)
//		//}
//		//for _, r := range bit0_red {
//		//	fmt.Printf("bit0_red: %s\n", r)
//		//}
//
//		mean_bit0_red, err := utils.SumBytes(bit0_red)
//		if err != nil {
//			return err
//		}
//		//fmt.Printf("%s\n", mean_bit0_red)
//		//fmt.Printf("time: %s\n", a.samples[0].time)
//		//os.Exit(1)
//		//fmt.Printf("sum1: %s\n", mean_bit0_red)
//		//fmt.Printf("sum1: %s\n", mean_bit0_red)
//		mean_bit0_red, _ = mean_bit0_red.Div(mean_bit0_red, big.NewInt(int64(len(bit0_red))))
//		//fmt.Printf("len: %d\n", len(bit0_red))
//		mean_bit0_nored, err := utils.SumBytes(bit0_nored)
//		if err != nil {
//			return err
//		}
//		mean_bit0_nored, _ = mean_bit0_nored.Div(mean_bit0_nored, big.NewInt(int64(len(bit0_nored))))
//
//		mean_bit1_red, err := utils.SumBytes(bit1_red)
//		if err != nil {
//			return err
//		}
//		mean_bit1_red, _ = mean_bit1_red.Div(mean_bit1_red, big.NewInt(int64(len(bit1_red))))
//		mean_bit1_nored, err := utils.SumBytes(bit1_nored)
//		if err != nil {
//			return err
//		}
//		mean_bit1_nored, _ = mean_bit1_nored.Div(mean_bit1_nored, big.NewInt(int64(len(bit1_nored))))
//
//		//fmt.Printf("sum1: %s\n", mean_bit0_red)
//		//fmt.Printf("sum2: %s\n", mean_bit1_red)
//
//		diff_0 := new(big.Int).Sub(mean_bit0_red, mean_bit0_nored)
//		diff_1 := new(big.Int).Sub(mean_bit1_red, mean_bit1_nored)
//
//		if diff_0.Cmp(diff_1) > 0 {
//			a.d.Mul(a.d, big.NewInt(2))
//			for i := range a.samples {
//				a.samples[i].curr = c_0[i]
//			}
//			n += 1
//		} else if diff_1.Cmp(diff_0) > 0 {
//			a.d.Mul(a.d, big.NewInt(2))
//			a.d.Add(a.d, big.NewInt(1))
//			for i := range a.samples {
//				a.samples[i].curr = c_1[i]
//			}
//			n += 1
//		} else {
//			panic("cant distinguish!")
//		}
//
//		if new(big.Int).Exp(a.c, new(big.Int).Mul(a.d, big.NewInt(2)), a.conf.N).Cmp(a.test_message) == 0 {
//			a.d.Mul(a.d, big.NewInt(2))
//			break
//		} else if new(big.Int).Exp(a.c, new(big.Int).Add(new(big.Int).Mul(a.d, big.NewInt(2)), big.NewInt(1)), a.conf.N).Cmp(a.test_message) == 0 {
//			a.d.Mul(a.d, big.NewInt(2))
//			a.d.Add(a.d, big.NewInt(1))
//			break
//		}
//	}
//	//}
//
//	return nil
//}

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

	//fmt.Printf("Key: [%X]\n", a.d.Bytes())

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
