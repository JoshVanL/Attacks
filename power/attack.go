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
	//"big"
	"math"
	//"time"
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
	SamplesI  = 40
	SamplesJ  = 1
	SamplesIJ = SamplesI * SamplesJ

	KeyByteLength = 16
	KeyGuesses    = 256

	CHUNKSIZE = 4
	CHUNKS    = 750
	SAMPLES   = 20
	KEY_RANGE = 256
	KEY_SIZE  = 16
	TRACE_NUM = 3000
)

type Hyps [SamplesIJ]byte

var (
	texts   [][]byte
	traces  [][]float64
	outputs [][]byte
	alen    int
	PC_h    [][]float64
	PC_a    [][]float64
	CC      [][]float64
)

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
	//foo := []float64{4, 4, 4, 6, 2, 5, 5, 6, 4, 4, 4, 5, 2, 4, 6, 5, 4, 4, 6, 5}
	//boo := []float64{3, 0, 7, 5, 5, 4, 9, 2, 2, 5, 7, 8, 0, 5, 6, 5, 7, 9, 6, 9}

	//c := Pearson(foo, boo)
	//fmt.Printf("%f\n", c)

	//os.Exit(0)

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

	//now := time.Nanoseconds()

	if err := a.GatherSamples(); err != nil {
		return utils.Error("failed to gather samples", err)
	}
	fmt.Printf("done.\n")

	a.AttackKey1()

	//fmt.Printf("Calculating Hypotheses...")
	//H := a.CalculateHypotheses()
	//fmt.Printf("done.\n")

	//fmt.Printf("Finding Key Bytes...\n")
	//a.FindKey(H)

	//fmt.Printf("\nAttack Complete.\n")
	//fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	////k := make(big.Int).SetBytes(a.key)
	////k := make([]byte, len(a.key)*2)
	////hex.Encode(k, a.key)

	//fmt.Printf("Target material: [%X]\n", a.key)
	//fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func (a *Attack) AttackKey1() {

	for i := 0; i < KEY_SIZE; i++ {
		a.attack_byte_phase1(i)
		a.attack_byte_phase2()

		var max float64
		index := 0
		for j := 0; j < KEY_RANGE; j++ {
			for k := 0; k < CHUNKS; k++ {
				if CC[j][k] > max {
					max = CC[j][k]
					index = j
				}
			}
		}

		fmt.Printf("%f %d\n", max, index)

	}


	////

	///
	//

}

func (a *Attack) attack_byte_phase2() {
	///

	//fmt.Printf("%d %d\n", len(traces), len(traces[0]))
	PC_a = transpose(traces)
	PC_a = PC_a[0:TRACE_NUM]
	//fmt.Printf("%d %d\n", len(PC_a), len(PC_a[0]))
	//os.Exit(1)
	CC = make([][]float64, KEY_RANGE)

	for i := 0; i < KEY_RANGE; i++ {
		CC[i] = make([]float64, TRACE_NUM)
		for j := 0; j < CHUNKS; j++ {
			corr := Pearson(PC_h[i], PC_a[j*CHUNKSIZE : (j+1)*CHUNKSIZE][0])
			CC[i][j] = corr
		}
	}

}

func (a *Attack) attack_byte_phase1(b int) {
	IV := make([][]byte, len(texts))
	HH := make([][]float64, len(texts))
	for i := 0; i < len(texts); i++ {
		IV[i] = make([]byte, KEY_RANGE)
		HH[i] = make([]float64, KEY_RANGE)
	}

	for i, p := range texts {
		p_i := p[b]

		for k := 0; k < KEY_RANGE; k++ {
			IV[i][k] = a.conf.SBox()[p_i^byte(k)]
			HH[i][k] = float64(utils.HammingWeight(IV[i][k]))
		}

	}

	//fmt.Printf("%d\n", len(IV))
	//fmt.Printf("%d\n", len(IV[0]))
	//fmt.Printf("%d\n", len(HH))
	//fmt.Printf("%d\n", len(HH[0]))
	////fmt.Printf("%v\n", HH)
	PC_h = transpose(HH)
	//fmt.Printf("%d %d\n", len(PC_h), len(PC_h[0]))
	////PC_h = make([][]float64, KEY_RANGE)
	////for i := 0; i < KEY_RANGE; i++ {
	////	//PC_h[i] =
	////}
	////H[i][j][k] = utils.HammingWeight(V[i][j][k])

	//os.Exit(1)

	////

}

func transpose(m [][]float64) [][]float64 {
	r := make([][]float64, len(m[0]))
	for x, _ := range r {
		r[x] = make([]float64, len(m))
	}
	for y, s := range m {
		for x, e := range s {
			r[x][y] = e
		}
	}
	return r
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

func (a *Attack) GatherSamples() os.Error {
	//samples := make([]*Sample, SamplesIJ)

	//count := 0

	//rnd := rand.New(rand.NewSource(time.Nanoseconds()))

	//for i := 0; i < SamplesI; i++ {
	//	for j := 0; j < SamplesJ; j++ {

	texts = make([][]byte, SAMPLES)
	traces = make([][]float64, SAMPLES)
	outputs = make([][]byte, SAMPLES)

	for i := 0; i < SAMPLES; i++ {
		//fmt.Printf("\rGathering Power Samples [%d]...", count)

		//inum := big.NewInt(int64(i))
		inum := utils.RandInt(2, 128)

		//l, ss, m, err := a.Interact(rnd.Int()%255, inum.Bytes())
		l, ss, m, err := a.Interact(inum.Bytes())
		if err != nil {
			return err
		}

		if l != len(ss) {
			return utils.NewError(fmt.Sprintf("l and length of trace, l=%d len(ss)=%d", l, len(ss)))
		}
		if alen == 0 {
			alen = l
		}

		if l != alen {
			return utils.NewError(fmt.Sprintf("in consistent l, l=%d alen=%d", l, alen))
		}

		oct := make([]byte, len(m)/2)
		hex.Decode(oct, m)

		outputs[i] = oct
		texts[i] = inum.Bytes()
		traces[i] = ss
		if len(texts[i]) == 15 {
			tmp := make([]byte, 16)
			copy(tmp[1:], texts[i])
			texts[i] = tmp
		}
	}

	//137671

	//fmt.Printf("\n%s\n", m)
	//fmt.Printf("%v\n", utils.HexToOct(m))
	//os.Exit(1)
	//tmp := make([]byte, len(m))
	//kk := 0
	//for k := len(m) - 1; k >= 0; k-- {
	//	tmp[kk] = m[k]
	//	kk++
	//}

	//foo := new(big.Int).SetBytes(oct)
	//if len(oct) != len(foo.Bytes()) {
	//	fmt.Printf("\n%v\n", oct)
	//	fmt.Printf("%v\n", foo.Bytes())
	//}
	//os.Exit(0)
	//fmt.Printf("\n%v\n", oct)
	//fmt.Printf("%v\n", tmp)

	//	samples[count] = &Sample{
	//		l: l,
	//		ss: ss,
	//		m: oct,
	//		//j: j,
	//		//i: inum,
	//	}
	//	count++
	//		}
	//	}

	//fmt.Printf("\rGathering Power Samples [%d]...", SamplesIJ)

	//a.samples = samples

	//for _, s := range samples[0].ss {
	//	fmt.Printf("%d\n", s)
	//}

	//fmt.Printf("%d\n", len(samples[0].m))

	return nil
}

func (a *Attack) Interact(i []byte) (l int, ss []float64, m []byte, err os.Error) {
	if err := a.Write(i); err != nil {
		return -1, nil, nil, err
	}

	l, ss, m, err = a.Read()
	if err != nil {
		return -1, nil, nil, err
	}

	a.interactions++

	return l, ss, m, nil
}

func (a *Attack) Write(sectorAddr []byte) os.Error {
	i := make([]byte, len(sectorAddr)*2)
	hex.Encode(i, sectorAddr)
	i = utils.Pad(bytes.AddByte(i, '\n'), 32)
	j := []byte{'0', '0', '0', '\n'}

	if err := a.cmd.WriteStdin(j); err != nil {
		return utils.Error("failed to write block adress", err)
	}

	if err := a.cmd.WriteStdin(i); err != nil {
		return utils.Error("failed to write sector address", err)
	}

	return nil
}

func (a *Attack) Read() (l int, ss []float64, m []byte, err os.Error) {
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

	var tmp float64
	for _, b := range p[start:] {
		if b != ',' {
			tmp = 10*tmp + (float64(b) - 48)
		} else {
			ss = utils.AppendFloat(ss, tmp)
			tmp = 0
		}
	}

	for {
		p, err := a.cmd.ReadStdout()
		if err != nil {
			return -1, nil, nil, utils.Error("failed to read power consumption", err)
		}
		for i, b := range p {
			if b == '\n' {
				if tmp != 0 {
					ss = utils.AppendFloat(ss, tmp)
				}
				m = bytes.Split(p[i+1:], []byte{'\n'}, 0)[0]
				//fmt.Printf("%v\n >%v\n", p, m)

				//close(stopCh)
				//wg.Wait()
				return l, ss, m, nil
			}

			if b != ',' {
				tmp = 10*tmp + (float64(b) - 48)
			} else {
				ss = utils.AppendFloat(ss, tmp)
				tmp = 0
			}
		}
	}

	return
}

func (a *Attack) printProgress(keyTry byte, i int) {
	str := ""
	for _, k := range a.key {
		str += fmt.Sprintf(" %X", k)
	}

	for i := 0; i < KeyByteLength-len(a.key); i++ {
		str += " *"
	}

	str += " "

	fmt.Printf("\r(%.2d) [%s] {%.3d} corr(%.4f) ", i, str, keyTry, a.maxGlobalCor)
}

func Pearson(a, b []float64) float64 {

	if len(a) != len(b) {
		panic("len(a) != len(b)")
	}

	var abar, bbar float64
	var n int
	for i := range a {
		if !math.IsNaN(a[i]) && !math.IsNaN(b[i]) {
			abar += a[i]
			bbar += b[i]
			n++
		}
	}
	nf := float64(n)
	abar, bbar = abar/nf, bbar/nf

	var numerator float64
	var sumAA, sumBB float64

	for i := range a {
		if !math.IsNaN(a[i]) && !math.IsNaN(b[i]) {
			numerator += (a[i] - abar) * (b[i] - bbar)
			sumAA += (a[i] - abar) * (a[i] - abar)
			sumBB += (b[i] - bbar) * (b[i] - bbar)
		}
	}

	return numerator / (math.Sqrt(sumAA) * math.Sqrt(sumBB))
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
		//for j := 1000; j < a.samples[0].l/40; j++ {
		for j := 0; j < 750; j++ {
			//for k := j*
			//for j := 0; j < 4; j++ {
			//	for k := j * CHUNKSIZE; k < (j+1)*CHUNKSIZE; k++ {
			//for j := 0; j < a.samples[0].l; j++ {
			//for j := 200; j < a.samples[0].l/50; j++ {
			//for j := a.samples[0].l - 1000; j >= a.samples[0].l-10000; j-- {
			//for j := 0; j < 1500; j++ {
			//go a.findCorrelationAtTime(j, h, wg)
			a.findCorrelationAtTime(j, H[i])
			//}
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

	fmt.Printf("%f\n", a.maxGlobalCor)
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
	c := Pearson(hh, ss)

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
