package main

import (
	"fmt"
	"big"
	"encoding/hex"
	"bytes"
	"os"
	"runtime"
	"time"
	"math"

	"./utils"
	"./time_c"
	"./command"
	"./montgomery"
)

const (
	WORD_LENGTH  = 256
	INIT_SAMPLES = 2000
	THRESHOLD    = 0.01
)

type Attack struct {
	cmd  *command.Command
	conf *time_c.Conf

	interactions int

	samples *Samples
	mnt     *montgomery.Montgomery

	bit0_reds []float64
	bit1_reds []float64
	tList0    []*big.Int
	tList1    []*big.Int
}

type Samples struct {
	xList    []*big.Int
	tList    []*big.Int
	fTList   []float64
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

func (a *Attack) generateSamples(samplesN int) os.Error {

	fmt.Printf("Generating samples [%d]...", samplesN)

	samples := new(Samples)
	t, _ := a.mnt.Mul(big.NewInt(1), a.mnt.Ro2)
	t, _ = a.mnt.Mul(t, t)

	for i := 0; i < samplesN; i++ {
		c := utils.RandInt(16, 128)

		_, tt, err := a.Interact(c)
		if err != nil {
			return utils.Error("error interacting for samples", err)
		}
		samples.fTList = utils.AppendFloat(samples.fTList, utils.BigIntToFloat(tt))

		x, _ := a.mnt.Mul(c, a.mnt.Ro2)
		samples.xList = utils.AppendBigInt(samples.xList, x)

		tmp, _ := a.mnt.Mul(t, x)
		samples.tList = utils.AppendBigInt(samples.tList, tmp)
	}

	a.samples = samples

	fmt.Printf("done.\n")

	return nil
}

func (a *Attack) findKey() (*big.Int, os.Error) {
	samplesN := INIT_SAMPLES

	for i := 0; i < 30; i++ {
		d, found := a.trySamples(samplesN)

		if found {
			return utils.BinaryStringToInt(d), nil
		}

		fmt.Printf("\nFailed to find key with this set.\n")

		samplesN += 1000
		if err := a.generateSamples(samplesN); err != nil {
			return nil, err
		}

	}

	return nil, utils.NewError("failed after 30 sets of samples, giving up.")
}

func (a *Attack) trySamples(samplesN int) (d string, found bool) {
	var diff float64

	d = "1"
	kSize := 1

	test_message := big.NewInt(12345)
	test_cipher := new(big.Int).Exp(test_message, a.conf.E, a.conf.N)

	a.printProgess(kSize, 0, "1")

	a.bit0_reds = make([]float64, samplesN)
	a.bit1_reds = make([]float64, samplesN)

	a.tList0 = make([]*big.Int, samplesN)
	a.tList1 = make([]*big.Int, samplesN)

	for {
		kSize++

		wg := utils.NewWaitGroup(samplesN)

		for i := 0; i < samplesN; i++ {
			go a.compute(i, wg)
		}

		runtime.Gosched()
		go wg.Wait()

		diff0 := a.correlation(a.bit0_reds)
		diff1 := a.correlation(a.bit1_reds)

		if diff0 > diff1 {
			d = fmt.Sprintf("%s0", d)
			a.printProgess(kSize, diff0, d)
			a.samples.tList = a.tList0
			diff = diff0
		} else {
			d = fmt.Sprintf("%s1", d)
			a.printProgess(kSize, diff1, d)
			a.samples.tList = a.tList1
			diff = diff1
		}

		k1 := utils.BinaryStringToInt(fmt.Sprintf("%s1", d))
		if new(big.Int).Exp(test_cipher, k1, a.conf.N).Cmp(test_message) == 0 {
			d = fmt.Sprintf("%s1", d)
			found = true
			break
		}

		k0 := utils.BinaryStringToInt(fmt.Sprintf("%s0", d))
		if new(big.Int).Exp(test_cipher, k0, a.conf.N).Cmp(test_message) == 0 {
			d = fmt.Sprintf("%s0", d)
			found = true
			break
		}

		if diff < THRESHOLD {
			found = false
			break
		}
	}

	return d, found
}

func (a *Attack) compute(i int, wg *utils.WaitGroup) {

	a.tList0[i], _ = a.mnt.Mul(a.samples.tList[i], a.samples.tList[i])

	a.tList1[i], _ = a.mnt.Mul(a.tList0[i], a.samples.xList[i])

	_, red0 := a.mnt.Mul(a.tList0[i], a.tList0[i])
	_, red1 := a.mnt.Mul(a.tList1[i], a.tList1[i])

	if red0 {
		a.bit0_reds[i] = 1
	} else {
		a.bit0_reds[i] = 0
	}

	if red1 {
		a.bit1_reds[i] = 1
	} else {
		a.bit1_reds[i] = 0
	}

	wg.Done()

	runtime.Goexit()
}

func (a *Attack) correlation(reds []float64) float64 {
	var R float64

	MM := make([]float64, len(reds))
	TT := make([]float64, len(reds))

	EM := utils.AverageFloat(reds)
	ET := utils.AverageFloat(a.samples.fTList)

	for i := range reds {
		R += (reds[i] - EM) * (a.samples.fTList[i] - ET)
	}

	R = R / float64(len(reds))

	for i := range reds {
		MM[i] = math.Pow(reds[i]-EM, 2)
		TT[i] = math.Pow(a.samples.fTList[i]-ET, 2)
	}

	varM := utils.AverageFloat(MM)
	varT := utils.AverageFloat(TT)

	return R / math.Sqrt(varM*varT)
}

func (a *Attack) printProgess(size int, diff float64, k string) {
	star := k
	for i := len(k); i < 59; i++ {
		star += "*"
	}

	fmt.Printf("\r(%.2d) [%s] diff(%.3f) ", size, star, diff)
}

func (a *Attack) Run() os.Error {
	if err := a.cmd.Run(); err != nil {
		return err
	}

	if err := a.generateSamples(INIT_SAMPLES); err != nil {
		return utils.Error("failed to generate samples", err)
	}

	now := time.Nanoseconds()

	fmt.Printf("Finding key...\n")
	d, err := a.findKey()
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

	runtime.GOMAXPROCS(2)

	if err := a.Run(); err != nil {
		utils.Fatal(err)
	}
}
