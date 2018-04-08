///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"big"
	"math"
	"time"
	"strings"
	"bytes"
	"strconv"
	"sync"

	"./command"
	"./power_c"
	"./utils"
)

const (
	Second    = int64(1e+9)
	SamplesI  = 50
	SamplesJ  = 1
	SamplesIJ = SamplesI * SamplesJ

	KeyByteLength = 16
	KeyGuesses    = 256
)

type Hyps [SamplesIJ]byte

type Attack struct {
	cmd  *command.Command
	conf *power_c.Conf

	//samples  []*Sample
	samples  *Samples
	keys     []byte
	localCor float64

	interactions int
	mx           *sync.Mutex
}

type Samples struct {
	l  int
	ss [][]int
	m  [][]byte
	//j  int
	//i  *big.Int
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

	keys := make([]byte, KeyGuesses)
	for i := 0; i < KeyGuesses; i++ {
		keys[i] = byte(i)
	}

	return &Attack{
		cmd: cmd,
		conf: power_c.NewConf(),
		keys: keys,
		interactions: 0,
		mx: new(sync.Mutex),
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

	if err := a.GatherSamples(); err != nil {
		return utils.Error("failed to gather samples", err)
	}
	fmt.Printf("done.\n")

	fmt.Printf("Calculating Hypotheses...")
	h := a.CalculateHypotheses()
	fmt.Printf("done.\n")
	a.FindKeyByte(h[0])

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	return nil
}

func (a *Attack) FindKeyByte(H []Hyps) byte {
	maxGlobalCor := float64(-10000)
	keyIndex := 0

	for i, h := range H {

		a.localCor = float64(-10)
		wg := utils.NewWaitGroup(a.samples.l)

		for j := 0; j < a.samples.l; j++ {
			go a.findCorrelationAtTime(j, h, wg)
		}

		runtime.Gosched()
		go wg.Wait()

		if a.localCor > maxGlobalCor {
			maxGlobalCor = a.localCor
			keyIndex = i
		}
	}

	fmt.Printf("%f\n", maxGlobalCor)
	fmt.Printf("%d\n", keyIndex)

	//for _, h := range H[0] {

	//}
	//for s := range a.samples {

	//}

	return 0
}

func (a *Attack) findCorrelationAtTime(j int, h Hyps, wg *utils.WaitGroup) {
	//ss := make([]int, SamplesIJ)
	//for k, sample := range a.samples.l {
	//	ss[k] = sample.ss[j]
	//}

	c := a.Corrolation(h, a.samples.ss[j])

	a.mx.Lock()
	if c > a.localCor {
		a.localCor = c
		//fmt.Printf("%f\n", c)
	}
	//a.localCor += c
	a.mx.Unlock()

	wg.Done()
	runtime.Goexit()
}

func (a *Attack) Corrolation(h Hyps, t []int) float64 {
	var R float64

	hh := make([]float64, len(h))
	tt := make([]float64, len(t))
	for i := range h {
		hh[i] = float64(h[i])
		tt[i] = float64(t[i])
	}

	HH := make([]float64, len(hh))
	TT := make([]float64, len(hh))
	EH := utils.AverageFloat(hh)
	ET := utils.AverageFloat(tt)

	for i := range hh {
		R += (hh[i] - EH) * (tt[i] - ET)
	}

	R = R / float64(len(hh))

	for i := range hh {
		HH[i] = math.Pow(hh[i]-EH, 2)
		TT[i] = math.Pow(tt[i]-ET, 2)
	}

	varH := utils.AverageFloat(HH)
	varT := utils.AverageFloat(TT)

	return R / math.Sqrt(varH*varT)
}

func (a *Attack) CalculateHypotheses() [][]Hyps {
	V := make([][]Hyps, KeyByteLength)
	H := make([][]Hyps, KeyByteLength)

	for i := range V {
		V[i] = make([]Hyps, KeyGuesses)
		H[i] = make([]Hyps, KeyGuesses)

		for j := 0; j < KeyGuesses; j++ {
			for k, m := range a.samples.m[i] {
				//fmt.Printf("%d\n", k)
				V[i][j][k] = a.conf.SBox()[a.keys[j]^m]
				H[i][j][k] = utils.HammingWeight(V[i][j][k])
				//fmt.Printf("%v %v\n", V[i][j][k], H[i][j][k])
			}
		}
	}

	return H
}

func (a *Attack) GatherSamples() os.Error {

	// Awkward memory allocation here for better memory access later
	count := 0
	samples := &Samples{
		m: make([][]byte, KeyByteLength),
	}

	for i := range samples.m {
		samples.m[i] = make([]byte, SamplesIJ)
	}

	for i := 0; i < SamplesI; i++ {
		for j := 0; j < SamplesJ; j++ {

			fmt.Printf("\rGathering Power Samples [%d]...", count)
			inum := big.NewInt(int64(i))

			l, ss, m, err := a.Interact(j, inum.Bytes())
			if err != nil {
				return err
			}

			if l != len(ss) {
				return utils.NewError(fmt.Sprintf("l and length of trace do not match, l=%d len(ss)=%d", l, len(ss)))
			}
			if l != samples.l && (j > 0 || i > 0) {
				return utils.NewError(fmt.Sprintf("l inconsistent with other samples, l=%d samples.l=%d", l, samples.l))
			}

			if i == 0 && j == 0 {
				samples.l = l
				samples.ss = make([][]int, l)

				for k := 0; k < l; k++ {
					samples.ss[k] = make([]int, SamplesIJ)
				}
			}

			for k := 0; k < l; k++ {
				samples.ss[k][count] = ss[k]
			}
			for k := 0; k < KeyByteLength; k++ {
				samples.m[k][count] = m[k]
			}

			count++

			//137671
		}
	}

	fmt.Printf("\rGathering Power Samples [%d]...", SamplesIJ)

	a.samples = samples

	//for _, s := range samples[0].ss {
	//	fmt.Printf("%d\n", s)
	//}

	//fmt.Printf("%d\n", len(samples[0].m))

	return nil
}

func (a *Attack) Interact(j int, i []byte) (l int, ss []int, m []byte, err os.Error) {
	if err := a.Write(j, i); err != nil {
		return -1, nil, nil, err
	}

	l, ss, m, err = a.Read()
	if err != nil {
		return -1, nil, nil, err
	}

	a.interactions++

	return l, ss, m, nil
}

func (a *Attack) Write(blockAddr int, sectorAddr []byte) os.Error {
	i := make([]byte, len(sectorAddr)*2)
	hex.Encode(i, sectorAddr)
	i = utils.Pad(bytes.AddByte(i, '\n'), 32)
	j := utils.AppendByte(utils.IntToBytes(blockAddr), '\n')

	if err := a.cmd.WriteStdin(j); err != nil {
		return utils.Error("failed to write block adress", err)
	}

	if err := a.cmd.WriteStdin(i); err != nil {
		return utils.Error("failed to write sector address", err)
	}

	return nil
}

func (a *Attack) Read() (l int, ss []int, m []byte, err os.Error) {
	p, err := a.cmd.ReadStdout()
	if err != nil {
		return -1, nil, nil, utils.Error("failed to read power consumption", err)
	}

	str := strings.Split(fmt.Sprintf("%s", p), ",", 0)
	l, err = strconv.Atoi(str[0])
	if err != nil {
		return -1, nil, nil, utils.Error("failed to convert power length integer string", err)
	}

	start := 0
	for i, b := range p {
		if b == ',' {
			start = i + 1
			break
		}
	}

	var tmp int
	for _, b := range p[start:] {
		if b != ',' {
			tmp = 10*tmp + (int(b) - 48)
		} else {
			ss = utils.AppendInt(ss, tmp)
			tmp = 0
		}
	}

	//stopCh := make(chan struct{})

	//wg := utils.NewWaitGroup(1)
	//go func() {
	//	ticker := time.NewTicker(Second * 3)
	//	for {
	//		select {
	//		case <-ticker.C:
	//			utils.Fatal(utils.NewError("reader time out"))
	//		case <-stopCh:
	//			wg.Done()
	//			return
	//		}
	//	}
	//}()

	for {
		p, err := a.cmd.ReadStdout()
		if err != nil {
			return -1, nil, nil, utils.Error("failed to read power consumption", err)
		}
		for i, b := range p {
			if b == '\n' {
				if tmp != 0 {
					ss = utils.AppendInt(ss, tmp)
				}
				m = bytes.Split(p[i+1:], []byte{'\n'}, 0)[0]

				//close(stopCh)
				//wg.Wait()
				return l, ss, m, nil
			}

			if b != ',' {
				tmp = 10*tmp + (int(b) - 48)
			} else {
				ss = utils.AppendInt(ss, tmp)
				tmp = 0
			}
		}
	}

	return
}
