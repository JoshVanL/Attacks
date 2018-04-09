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
	"math"
	"time"
	"strings"
	"bytes"
	"strconv"

	"./command"
	"./power_c"
	"./utils"
)

const (
	CHUNKSIZE    = 4
	MESSAGE_SIZE = 16
	CHUNKS       = 750
	SAMPLES      = 30
	KEY_RANGE    = 256
	KEY_SIZE     = 16
	TRACE_NUM    = 3000
)

type Attack struct {
	cmd  *command.Command
	conf *power_c.Conf

	samples *Samples
	corr    float64

	interactions int
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

	fmt.Printf("Finding Key...\n")
	k2 := a.FindKey()

	fmt.Printf("\nAttack Complete.\n")
	fmt.Printf("Confidence: %.2f%%\n", (a.corr/KEY_SIZE)*100)
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float64((time.Nanoseconds()-now))/1e9)

	fmt.Printf("Target material: [%X]\n", k2)
	fmt.Printf("Interactions: %d\n", a.interactions)

	return nil
}

func (a *Attack) FindKey() []byte {
	var k2 []byte

	var max float64
	var key byte

	a.printProgress(k2, 0, 1)

	for i := 0; i < KEY_SIZE; i++ {
		a.CalculateKeyCorrelations(i)
		max = 0

		for j := 0; j < KEY_RANGE; j++ {
			for k := 0; k < TRACE_NUM; k++ {
				if a.samples.CC[j][k] > max {
					max = a.samples.CC[j][k]
					key = byte(j)
				}
			}
			a.printProgress(k2, max, i+1)
		}

		k2 = bytes.AddByte(k2, key)
		a.corr += max
	}

	a.printProgress(k2, max, KEY_SIZE)

	return k2
}

func (a *Attack) CalculateKeyCorrelations(b int) {
	for i, p := range a.samples.inputs {
		p_i := p[b]

		for k := 0; k < KEY_RANGE; k++ {
			a.samples.HH[i][k] = float64(utils.HammingWeight(a.conf.SBox()[p_i^byte(k)]))
		}

	}

	HHT := utils.Transpose(a.samples.HH)
	a.samples.TT = utils.Transpose(a.samples.traces)[0:TRACE_NUM]

	a.samples.CC = make([][]float64, KEY_RANGE)

	for i := 0; i < KEY_RANGE; i++ {
		a.samples.CC[i] = make([]float64, TRACE_NUM)
		for j := 0; j < TRACE_NUM; j++ {
			corr := Correlation(HHT[i], a.samples.TT[j*CHUNKSIZE : (j+1)*CHUNKSIZE][0])
			a.samples.CC[i][j] = corr
		}
	}
}


func Correlation(a []float64, b []float64) float64 {
	var aEx, bEx, AA, BB, R float64

	for i := range a {
		aEx += a[i]
		bEx += b[i]
	}

	aEx = aEx / float64(len(a))
	bEx = bEx / float64(len(b))

	for i := range a {
		R += (a[i] - aEx) * (b[i] - bEx)
		AA += (a[i] - aEx) * (a[i] - aEx)
		BB += (b[i] - bEx) * (b[i] - bEx)
	}

	return R / (math.Sqrt(AA) * math.Sqrt(BB))
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
