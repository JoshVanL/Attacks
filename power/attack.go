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
	"crypto/aes"
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
	//Second    = int64(1e+9)
	//SamplesI  = 40
	//SamplesJ  = 1
	//SamplesIJ = SamplesI * SamplesJ

	//KeyByteLength = 16
	//KeyGuesses    = 256

	CHUNKSIZE    = 4
	MESSAGE_SIZE = 16
	CHUNKS       = 750
	SAMPLES      = 20
	KEY_RANGE    = 256
	KEY_SIZE     = 16
	TRACE_NUM    = 3000
)

type Attack struct {
	cmd  *command.Command
	conf *power_c.Conf

	samples   *Samples
	corrCount int

	interactions int
	mx           *sync.Mutex
}

type Samples struct {
	inputs  [][]byte
	outputs [][]byte

	l      int
	traces [][]float64

	HH [][]float64
	TT [][]float64
	CC [][]float64
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

	return &Attack{
		cmd: cmd,
		conf: power_c.NewConf(),
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

	fmt.Printf("Finding Key 2...\n")
	k2 := a.FindKey2()

	fmt.Printf("\nFinding Key 1...\n")
	k1, err := a.FindKey1(k2)
	if err != nil {
		return utils.Error("failed to find key 1", err)
	}

	fmt.Printf("\nAttack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	fmt.Printf("Target material: [%X]\n", k2)
	fmt.Printf("Target material: [%X]\n", k1)
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func (a *Attack) FindKey1(k2 []byte) ([]byte, os.Error) {
	var k1 []byte

	var max float64
	var key byte

	tweaks, err := a.GenerateTweaks(k2)
	if err != nil {
		return nil, err
	}

	for i := 0; i < KEY_SIZE; i++ {
		a.CalculateKey1Correlations(i, tweaks)
		max = 0

		for j := 0; j < KEY_RANGE; j++ {
			for k := 0; k < CHUNKS; k++ {
				if a.samples.CC[j][k] > max {
					max = a.samples.CC[j][k]
					key = byte(j)
				}
			}
			a.printProgress(k1, max, i+1)
		}

		k1 = bytes.AddByte(k1, key)
	}

	a.printProgress(k1, max, KEY_SIZE)

	return k1, nil
}

func (a *Attack) CalculateKey1Correlations(b int, tweaks [][]byte) {
	for i, p := range a.samples.outputs {
		p_i := p[b]

		for k := 0; k < KEY_RANGE; k++ {
			a.samples.HH[i][k] = float64(utils.HammingWeight(a.conf.SBox()[(p_i^tweaks[i][b])^byte(k)]))
		}

	}

	HHT := transpose(a.samples.HH)
	a.samples.TT = transpose(a.samples.traces)
	a.samples.TT = a.samples.TT[len(a.samples.traces[0])-TRACE_NUM : len(a.samples.traces[0])]

	a.samples.CC = make([][]float64, KEY_RANGE)

	for i := 0; i < KEY_RANGE; i++ {
		a.samples.CC[i] = make([]float64, TRACE_NUM)
		for j := 0; j < CHUNKS; j++ {
			corr := Pearson(HHT[i], a.samples.TT[j*CHUNKSIZE : (j+1)*CHUNKSIZE][0])
			a.samples.CC[i][j] = corr
		}
	}
}

func (a *Attack) GenerateTweaks(key []byte) ([][]byte, os.Error) {
	tweaks := make([][]byte, SAMPLES)

	k, err := aes.NewCipher(key)
	if err != nil {
		return nil, utils.Error("failed to create new AES cipher for tweaks", err)
	}

	for i, input := range a.samples.inputs {
		tweaks[i] = make([]byte, MESSAGE_SIZE)
		k.Encrypt(input, tweaks[i])
	}

	return tweaks, nil
}

func (a *Attack) FindKey2() []byte {
	var k2 []byte

	var max float64
	var key byte

	for i := 0; i < KEY_SIZE; i++ {
		a.CalculateKey2Correlations(i)
		max = 0

		for j := 0; j < KEY_RANGE; j++ {
			for k := 0; k < CHUNKS; k++ {
				if a.samples.CC[j][k] > max {
					max = a.samples.CC[j][k]
					key = byte(j)
				}
			}
			a.printProgress(k2, max, i+1)
		}

		k2 = bytes.AddByte(k2, key)
	}

	a.printProgress(k2, max, KEY_SIZE)

	return k2
}

func (a *Attack) CalculateKey2Correlations(b int) {
	for i, p := range a.samples.inputs {
		p_i := p[b]

		for k := 0; k < KEY_RANGE; k++ {
			a.samples.HH[i][k] = float64(utils.HammingWeight(a.conf.SBox()[p_i^byte(k)]))
		}

	}

	HHT := transpose(a.samples.HH)
	a.samples.TT = transpose(a.samples.traces)
	a.samples.TT = a.samples.TT[0:TRACE_NUM]

	a.samples.CC = make([][]float64, KEY_RANGE)

	for i := 0; i < KEY_RANGE; i++ {
		a.samples.CC[i] = make([]float64, TRACE_NUM)
		for j := 0; j < CHUNKS; j++ {
			corr := Pearson(HHT[i], a.samples.TT[j*CHUNKSIZE : (j+1)*CHUNKSIZE][0])
			a.samples.CC[i][j] = corr
		}
	}
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

func (a *Attack) Correlation(hh []float64, tt []float64) float64 {
	var R float64

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

func (a *Attack) GatherSamples() os.Error {

	samples := &Samples{
		inputs: make([][]byte, SAMPLES),
		traces: make([][]float64, SAMPLES),
		outputs: make([][]byte, SAMPLES),
		HH: make([][]float64, SAMPLES),
	}

	for i := 0; i < SAMPLES; i++ {
		fmt.Printf("\rGathering Power Samples [%d]...", i)

		samples.HH[i] = make([]float64, KEY_RANGE)
		j := utils.RandInt(2, 128)

		l, ss, m, err := a.Interact(j.Bytes())
		if err != nil {
			return err
		}

		if l != len(ss) {
			return utils.NewError(fmt.Sprintf("l and length of trace, l=%d len(ss)=%d", l, len(ss)))
		}
		if samples.l == 0 {
			samples.l = l
		}

		if l != samples.l {
			return utils.NewError(fmt.Sprintf("in consistent l, l=%d alen=%d", l, samples.l))
		}

		oct := make([]byte, len(m)/2)
		samples.inputs[i] = make([]byte, MESSAGE_SIZE)
		hex.Decode(oct, m)

		samples.outputs[i] = oct
		samples.traces[i] = ss
		copy(samples.inputs[i][MESSAGE_SIZE-len(j.Bytes()):], j.Bytes())
	}

	fmt.Printf("\rGathering Power Samples [%d]...", SAMPLES)

	a.samples = samples

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

func (a *Attack) printProgress(key []byte, corr float64, i int) {
	str := ""
	for _, k := range key {
		str += fmt.Sprintf(" %X", k)
	}

	for i := 0; i < KEY_SIZE-len(key); i++ {
		str += " **"
	}

	str += " "

	fmt.Printf("\r(%.2d) [%s] (%.3f)  ", i, str, corr)
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
