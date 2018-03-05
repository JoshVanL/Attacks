package main

import (
	"fmt"
	"big"
	"encoding/hex"
	"bytes"
	"os"
	"time"

	"./utils"
	"./time_c"
	"./command"
	"./montgomery"
)

const (
	WORD_LENGTH  = 256
	INIT_SAMPLES = 2500
)

type Attack struct {
	cmd  *command.Command
	conf *time_c.Conf

	interactions int

	samples *Samples
	mnt     *montgomery.Montgomery
}

type Samples struct {
	xList    []*big.Int
	tList    []*big.Int
	cList    []*big.Int
	timeList []*big.Int
	messages []*big.Int
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

func (a *Attack) Interact(c *big.Int) (m []byte, t *big.Int, err os.Error) {
	n := make([]byte, len(c.Bytes())*2)
	hex.Encode(n, c.Bytes())
	n = utils.Pad(bytes.AddByte(n, '\n'), WORD_LENGTH)

	if err := a.Write(n); err != nil {
		return nil, nil, err
	}

	tb, mb, err := a.Read()
	if err != nil {
		return nil, nil, err
	}

	t, err = utils.BytesToInt(tb)
	if err != nil {
		return nil, nil, utils.Error("failed to convert time bytes", err)
	}

	a.interactions++

	return mb, t, nil
}

func (a *Attack) generate_samples(samplesN int) os.Error {

	fmt.Printf("Generating samples [%d]...", samplesN)

	samples := new(Samples)
	t, _ := a.mnt.Mul(big.NewInt(1), a.mnt.Ro2)

	for i := 0; i < samplesN; i++ {
		c := utils.RandInt(16, 128)
		_, tt, err := a.Interact(c)
		if err != nil {
			return utils.Error("error interacting for samples", err)
		}
		samples.cList = utils.AppendBigInt(samples.cList, c)
		samples.timeList = utils.AppendBigInt(samples.timeList, tt)
		xHat, _ := a.mnt.Mul(c, a.mnt.Ro2)
		tTemp, _ := a.mnt.Mul(t, t)
		tTemp, _ = a.mnt.Mul(tTemp, xHat)
		samples.xList = utils.AppendBigInt(samples.xList, xHat)
		samples.tList = utils.AppendBigInt(samples.tList, tTemp)
	}

	a.samples = samples

	fmt.Printf("done.\n")

	return nil
}

func (a *Attack) find_key() (*big.Int, os.Error) {
	samplesN := INIT_SAMPLES

	for i := 0; i < 30; i++ {
		d, found, err := a.try_samples(samplesN)
		if err != nil {
			return nil, err
		}

		if found {
			return utils.BinaryStringToInt(d), nil
		}

		samplesN += 1000
		fmt.Printf("\nFailed to find key with this set.\n")
		if err := a.generate_samples(samplesN); err != nil {
			return nil, err
		}

	}

	return nil, utils.NewError("failed after 30 sets of samples, giving up.")
}

func (a *Attack) try_samples(samplesN int) (d string, found bool, err os.Error) {
	var diff *big.Int
	d = "1"
	kSize := 1

	test_message := big.NewInt(12345)
	test_cipher := new(big.Int).Exp(test_message, a.conf.E, a.conf.N)

	a.printProgess(kSize, big.NewInt(0), "1")

	for {
		kSize++
		var bit0_red []*big.Int
		var bit0_nored []*big.Int
		var bit1_red []*big.Int
		var bit1_nored []*big.Int

		tList0 := make([]*big.Int, samplesN)
		tList1 := make([]*big.Int, samplesN)

		for i := 0; i < samplesN; i++ {
			t := a.samples.tList[i]
			tt := a.samples.timeList[i]

			t0, _ := a.mnt.Mul(t, t)
			tList0[i] = t0

			t1, _ := a.mnt.Mul(t0, a.samples.xList[i])
			tList1[i] = t1

			_, red0 := a.mnt.Mul(t0, t0)
			_, red1 := a.mnt.Mul(t1, t1)

			if red0 {
				bit0_red = utils.AppendBigInt(bit0_red, tt)
			} else {
				bit0_nored = utils.AppendBigInt(bit0_nored, tt)
			}

			if red1 {
				bit1_red = utils.AppendBigInt(bit1_red, tt)
			} else {
				bit1_nored = utils.AppendBigInt(bit1_nored, tt)
			}
		}

		diff0 := new(big.Int).Sub(utils.Average(bit0_red), utils.Average(bit0_nored))
		diff1 := new(big.Int).Sub(utils.Average(bit1_red), utils.Average(bit1_nored))

		if diff0.Cmp(diff1) > 0 {
			d = fmt.Sprintf("%s0", d)
			a.printProgess(kSize, diff0, d)
			a.samples.tList = tList0
			diff = diff0
		} else {
			d = fmt.Sprintf("%s1", d)
			a.printProgess(kSize, diff1, d)
			a.samples.tList = tList1
			diff = diff1
		}

		k1 := utils.BinaryStringToInt(fmt.Sprintf("%s1", d))
		if new(big.Int).Exp(test_cipher, k1, a.conf.N).Cmp(test_message) == 0 {
			d = fmt.Sprintf("%s1", d)
			return d, true, nil
		}

		k0 := utils.BinaryStringToInt(fmt.Sprintf("%s0", d))
		if new(big.Int).Exp(test_cipher, k0, a.conf.N).Cmp(test_message) == 0 {
			d = fmt.Sprintf("%s0", d)
			return d, true, nil
		}

		if diff.Cmp(big.NewInt(2)) < 0 {
			return "", false, nil
		}
		//92319c502a2f137
	}

	return "", false, utils.NewError("couldn't find key")
}

func (a *Attack) printProgess(size int, diff *big.Int, k string) {
	star := k
	for i := len(k); i < 59; i++ {
		star += "*"
	}

	fmt.Printf("\r(%.2d) [%s] diff(%s) ", size, star, diff)
}

func (a *Attack) Run() os.Error {
	if err := a.cmd.Run(); err != nil {
		return err
	}

	if err := a.generate_samples(INIT_SAMPLES); err != nil {
		return utils.Error("failed to generate samples", err)
	}

	now := time.Nanoseconds()

	fmt.Printf("Finding key...\n")
	d, err := a.find_key()
	if err != nil {
		return utils.Error("error finding key", err)
	}
	fmt.Printf("\nKey found.\n")
	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	fmt.Printf("Target material: [%X]\n", d.Bytes())
	fmt.Printf("Interactions: %d\n", a.interactions)

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
