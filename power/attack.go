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
	"big"
	"time"
	"strings"
	"bytes"
	"strconv"

	"./command"
	"./power_c"
	"./utils"
)

const (
	Second    = int64(1e+9)
	SamplesI  = 50
	SamplesJ  = 1
	SamplesIJ = SamplesI * SamplesJ

	KeyLengthByte  = 16
	KeyLengthBit   = 128
	KeyByteGuesses = 256
)

//type KeyByte byte

type Attack struct {
	cmd  *command.Command
	conf *power_c.Conf

	samples []*Sample
	keys    []byte

	interactions int
}

type Sample struct {
	l  int
	ss []int
	m  []byte
	j  int
	i  *big.Int
}

func main() {
	fmt.Printf("Initialising attack...")
	a, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")

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

	keys := make([]byte, KeyByteGuesses)
	for i := 0; i < KeyByteGuesses; i++ {
		keys[i] = byte(i)
	}

	return &Attack{
		cmd: cmd,
		conf: power_c.NewConf(),
		keys: keys,
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

	fmt.Printf("Calculating Hypotheses...")
	a.CalculateHypotheses()
	fmt.Printf("done.\n")

	fmt.Printf("Attack Complete.\n")
	fmt.Printf("Elapsed time: %.2fs\n*********\n", float((time.Nanoseconds()-now))/1e9)

	return nil
}

func (a *Attack) FindKeyByte(H [][]byte) byte {
	//for s := range a.samples {

	//}

	return 0
}

func (a *Attack) Corrolation(h []byte, s []int) float64 {
	//

	return 0
}

func (a *Attack) CalculateHypotheses() [][][]byte {
	V := make([][][]byte, SamplesIJ)
	H := make([][][]byte, SamplesIJ)

	for i := range V {
		V[i] = make([][]byte, KeyByteGuesses)
		H[i] = make([][]byte, KeyByteGuesses)

		for j := range V[i] {
			V[i][j] = make([]byte, len(a.samples[i].m))
			H[i][j] = make([]byte, len(a.samples[i].m))

			for k, m := range a.samples[i].m {
				V[i][j][k] = a.conf.SBox()[a.keys[j]^m]
				H[i][j][k] = V[i][j][k] & 1
			}
			//fmt.Printf("%v %v\n", V[i][j], H[i][j])
		}
	}

	return nil
}

func (a *Attack) GatherSamples() os.Error {
	samples := make([]*Sample, SamplesIJ)

	count := 0

	for i := 0; i < SamplesI; i++ {
		for j := 0; j < SamplesJ; j++ {

			fmt.Printf("\rGathering Power Samples [%d]...", count)
			count++

			inum := big.NewInt(int64(i))

			l, ss, m, err := a.Interact(j, inum.Bytes())
			if err != nil {
				return err
			}

			if l != len(ss) {
				return utils.NewError(fmt.Sprintf("l and length of trace, l=%d len(ss)=%d", l, len(ss)))
			}

			//137671

			samples[i+SamplesI*j] = &Sample{
				l: l,
				ss: ss,
				m: utils.HexToOct(m),
				j: j,
				i: inum,
			}
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

	stopCh := make(chan struct{})

	wg := utils.NewWaitGroup(1)
	go func() {
		ticker := time.NewTicker(Second * 3)
		for {
			select {
			case <-ticker.C:
				utils.Fatal(utils.NewError("reader time out"))
			case <-stopCh:
				wg.Done()
				return
			}
		}
	}()

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

				close(stopCh)
				wg.Wait()
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
