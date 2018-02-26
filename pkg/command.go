package command

import (
	"fmt"
	"exec"
	"os"

	"./utils"
)

type Command struct {
	cmd  *exec.Cmd
	file string
}

func NewCommand(file string) (*Command, os.Error) {
	if _, err := exec.LookPath(file); err != nil {
		return nil, utils.Error(fmt.Sprintf("error looking up binary file '%s'", file), err)
	}

	return &Command{
		file: file,
	},
		nil
}

func (c *Command) Run() os.Error {
	cmd, err := exec.Run(c.file, []string{}, nil, exec.Pipe, exec.Pipe, exec.Pipe)
	if err != nil {
		return utils.Error(fmt.Sprintf("error running command '%s'", c.file), err)
	}

	c.cmd = cmd

	return nil
}

func (c *Command) WriteStdin(b []byte) os.Error {
	if _, err := c.cmd.Stdin.Write(b); err != nil {
		return utils.Error("error writing bytes to command stdin", err)
	}

	return nil
}

func (c *Command) Read() ([]byte, os.Error) {
	b := make([]byte, 1024)

	if _, err := c.cmd.Stdout.Read(b); err != nil {
		return nil, utils.Error("error reading command stdout", err)
	}

	return b, nil
}

func (c *Command) Kill() os.Error {
	if _, err := c.cmd.Wait(os.WNOHANG); err != nil {
		return utils.Error("error closing running command", err)
	}

	return nil
}
