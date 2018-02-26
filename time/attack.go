package main

import (
	"fmt"
	"os"

	"./utils"
	"./time_c"
	"./command"
)

type Attack struct {
	cmd *command.Command

	attackFile string
	conf       *time_c.Conf

	interactions int
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

	return &Attack{
		attackFile: args[0],
		conf: conf,
		interactions: 0,
	},
		nil
}

func main() {
	fmt.Printf("Initalising attack...\n")
	_, err := NewAttack()
	if err != nil {
		utils.Fatal(err)
	}
}
