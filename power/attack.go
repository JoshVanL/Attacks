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
	//"rand"
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
	SamplesJ  = 2
	SamplesIJ = SamplesI * SamplesJ

	KeyByteLength = 16
	KeyGuesses    = 256
)

type Hyps [SamplesIJ]byte

type Attack struct {
	cmd  *command.Command
	conf *power_c.Conf

	samples      []*Sample
	keys         []byte
	maxLocalCor  float64
	maxGlobalCor float64
	corrCount    int

	key []byte

	interactions int
	thej         int
	mx           *sync.Mutex
}

type Sample struct {
	l  int
	ss []int
	m  []byte
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

	runtime.GOMAXPROCS(1)

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
	H := a.CalculateHypotheses()
	fmt.Printf("done.\n")

	fmt.Printf("Finding Key Bytes...\n")
	a.FindKey(H)

	fmt.Printf("\nAttack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	//k := make(big.Int).SetBytes(a.key)
	//k := make([]byte, len(a.key)*2)
	//hex.Encode(k, a.key)

	fmt.Printf("Target material: [%X]\n", a.key)
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func (a *Attack) FindKey(H [][]Hyps) {
	for i := 0; i < KeyByteLength; i++ {
		k := a.FindKeyByte(H[i], i)
		a.key = bytes.AddByte(a.key, k)
		a.printProgress(a.keys[KeyGuesses-1], i+1)
	}

}

func (a *Attack) FindKeyByte(H []Hyps, index int) byte {
	a.maxGlobalCor = float64(-10000)
	keyIndex := 0

	for i := 0; i < KeyGuesses; i++ {

		//fmt.Printf("\rTrying Key[%d]", a.keys[i])

		//a.maxLocalCor = float64(-10000)
		a.maxLocalCor = float64(0)
		//wg := utils.NewWaitGroup(a.samples[0].l)
		//wg := utils.NewWaitGroup(3000)

		a.corrCount = 0
		for j := 1000; j < a.samples[0].l/40; j++ {
			//for j := 200; j < a.samples[0].l/50; j++ {
			//for j := a.samples[0].l - 1000; j >= a.samples[0].l-10000; j-- {
			//for j := 0; j < 1500; j++ {
			//go a.findCorrelationAtTime(j, h, wg)
			a.findCorrelationAtTime(j, H[i])
		}

		//runtime.Gosched()
		//go wg.Wait()
		//wg.Wait()
		//fmt.Printf("%d ", a.corrCount)

		//fmt.Printf("%f %d \n", a.maxLocalCor, a.thej)
		if a.maxLocalCor > a.maxGlobalCor {
			a.maxGlobalCor = a.maxLocalCor
			keyIndex = i
		}

		a.printProgress(a.keys[i], index+1)
	}


	//fmt.Printf("%f\n", maxGlobalCor)
	//fmt.Printf("%d\n", keyIndex)

	//for _, h := range H[0] {

	//}
	//for s := range a.samples {

	//}

	return a.keys[keyIndex]
}

func (a *Attack) findCorrelationAtTime(j int, h Hyps) {
	ss := make([]float64, len(a.samples))
	hh := make([]float64, len(h))
	//f := 0
	//for k := len(a.samples) - 1; k > 0; k-- {
	//	ss[f] = a.samples[k].ss[j]
	//	//f++
	//}

	for k, sample := range a.samples {
		ss[k] = float64(sample.ss[j])
	}

	for k := range h {
		hh[k] = float64(h[k])
	}
	//c := a.Corrolation(h, ss)
	c := Correlation(hh, ss, nil)
	//if c < 0 {
	//	//fmt.Printf("%f\n", c)
	//	c = -c
	//}

	//a.mx.Lock()
	if c > a.maxLocalCor { // && c > 0.5 {
		//if c > 0.5 {
		a.maxLocalCor = c
		a.thej = j
		//a.maxLocalCor += c
		a.corrCount++
	}
	//a.mx.Unlock()

	//wg.Done()
	//runtime.Goexit()
}

func (a *Attack) Corrolation(h Hyps, t []int) float64 {
	var R float64

	hh := make([]float64, len(h))
	tt := make([]float64, len(t))
	for i := range h {
		hh[i] = float64(h[i])
		tt[i] = float64(t[i])
	}

	//c := 0
	//for i := len(h) - 1; i >= 0; i-- {
	//	hh[c] = float64(h[i])
	//	c++
	//}

	HH := make([]float64, len(hh))
	TT := make([]float64, len(hh))
	//var HH float64
	//var TT float64
	EH := utils.AverageFloat(hh)
	ET := utils.AverageFloat(tt)

	for i := range hh {
		R += (hh[i] - EH) * (tt[i] - ET)
	}

	R = R / float64(len(hh))

	for i := range hh {
		HH[i] = math.Pow(hh[i]-EH, 2)
		TT[i] = math.Pow(tt[i]-ET, 2)
		//HH += math.Pow(hh[i]-EH, 2)
		//TT += math.Pow(tt[i]-ET, 2)
	}

	varH := utils.AverageFloat(HH)
	varT := utils.AverageFloat(TT)

	return R / math.Sqrt(varH*varT)
	//return R / (math.Sqrt(HH) * math.Sqrt(TT))
}

func (a *Attack) CalculateHypotheses() [][]Hyps {
	V := make([][]Hyps, KeyByteLength)
	H := make([][]Hyps, KeyByteLength)

	for i := range V {
		V[i] = make([]Hyps, KeyGuesses)
		H[i] = make([]Hyps, KeyGuesses)

		for j := 0; j < KeyGuesses; j++ {
			for k, sample := range a.samples {
				V[i][j][k] = a.conf.SBox()[a.keys[j]^sample.m[i]]
				//V[i][j][k] = a.conf.RoundConstant()[a.keys[j]^sample.m[i]]
				H[i][j][k] = utils.HammingWeight(V[i][j][k])
				//H[i][j][k] = V[i][j][k] & 1
				//fmt.Printf("\n%v\n", V[i][j][k])
				//fmt.Printf("%v\n", H[i][j][k])
				//fmt.Printf("%v %v\n", V[i][j][k], H[i][j][k])
			}
		}
	}

	return H
}

func (a *Attack) GatherSamples() os.Error {
	samples := make([]*Sample, SamplesIJ)

	count := 0

	//rnd := rand.New(rand.NewSource(time.Nanoseconds()))

	for i := 0; i < SamplesI; i++ {
		for j := 0; j < SamplesJ; j++ {

			fmt.Printf("\rGathering Power Samples [%d]...", count)

			inum := big.NewInt(int64(i))
			//inum := utils.RandInt(2, 24)

			//l, ss, m, err := a.Interact(rnd.Int()%255, inum.Bytes())
			l, ss, m, err := a.Interact(j, inum.Bytes())
			if err != nil {
				return err
			}

			if l != len(ss) {
				return utils.NewError(fmt.Sprintf("l and length of trace, l=%d len(ss)=%d", l, len(ss)))
			}

			//137671

			//fmt.Printf("\n%s\n", m)
			//fmt.Printf("%v\n", utils.HexToOct(m))
			//os.Exit(1)
			tmp := make([]byte, len(m))
			kk := 0
			for k := len(m) - 1; k >= 0; k-- {
				tmp[kk] = m[k]
				kk++
			}

			oct := make([]byte, len(m)/2)
			hex.Decode(oct, m)
			//fmt.Printf("\n%v\n", oct)
			//fmt.Printf("%v\n", tmp)

			samples[count] = &Sample{
				l: l,
				ss: ss,
				m: oct,
				//j: j,
				//i: inum,
			}
			count++
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
func Correlation(x, y, weights []float64) float64 {
	// This is a two-pass corrected implementation.  It is an adaptation of the
	// algorithm used in the MeanVariance function, which applies a correction
	// to the typical two pass approach.

	if len(x) != len(y) {
		panic("stat: slice length mismatch")
	}
	xu := utils.AverageFloat(x)
	yu := utils.AverageFloat(y)
	var (
		sxx           float64
		syy           float64
		sxy           float64
		xcompensation float64
		ycompensation float64
	)
	if weights == nil {
		for i, xv := range x {
			yv := y[i]
			xd := xv - xu
			yd := yv - yu
			sxx += xd * xd
			syy += yd * yd
			sxy += xd * yd
			xcompensation += xd
			ycompensation += yd
		}
		// xcompensation and ycompensation are from Chan, et. al.
		// referenced in the MeanVariance function.  They are analogous
		// to the second term in (1.7) in that paper.
		sxx -= xcompensation * xcompensation / float64(len(x))
		syy -= ycompensation * ycompensation / float64(len(x))

		return (sxy - xcompensation*ycompensation/float64(len(x))) / math.Sqrt(sxx*syy)

	}

	var sumWeights float64
	for i, xv := range x {
		w := weights[i]
		yv := y[i]
		xd := xv - xu
		wxd := w * xd
		yd := yv - yu
		wyd := w * yd
		sxx += wxd * xd
		syy += wyd * yd
		sxy += wxd * yd
		xcompensation += wxd
		ycompensation += wyd
		sumWeights += w
	}
	// xcompensation and ycompensation are from Chan, et. al.
	// referenced in the MeanVariance function.  They are analogous
	// to the second term in (1.7) in that paper, except they use
	// the sumWeights instead of the sample count.
	sxx -= xcompensation * xcompensation / sumWeights
	syy -= ycompensation * ycompensation / sumWeights

	return (sxy - xcompensation*ycompensation/sumWeights) / math.Sqrt(sxx*syy)
}

func (a *Attack) printProgress(keyTry byte, i int) {
	str := ""
	for _, k := range a.key {
		str += fmt.Sprintf(" %v", k)
	}

	for i := 0; i < KeyByteLength-len(a.key); i++ {
		str += " *"
	}

	str += " "

	fmt.Printf("\r(%.2d) [%s] {%.3d} corr(%.4f) ", i, str, keyTry, a.maxGlobalCor)
}
