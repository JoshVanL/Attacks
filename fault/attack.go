///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package main

import (
	//"big"
	//"bytes"
	//"encoding/hex"
	"fmt"
	//"math"
	"os"
	//"runtime"
	//"time"

	"./command"
	"./utils"
)

type Attack struct {
	cmd *command.Command

	interactions int
}

func main() {
	fmt.Printf("Initalising attack...")
	_, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}
	fmt.Printf("done.\n")
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
		cmd:          cmd,
		interactions: 0,
	}, nil
}
