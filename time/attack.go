package main

import (
	"fmt"
)


type Attack struct {
	cmd *command.Command

	attackFile string
	conf       *oaep.Conf

	interactions int
}
