package file

import (
	"os"
	"bufio"
	"fmt"
	"big"
	"syscall"

	"./utils"
)

const (
	NewLine = byte(10)
	Base    = 16
)


type FileReader struct {
	file     *os.File
	filename string
	reader   *bufio.Reader
}

func NewFileReader(filename string) (*FileReader, os.Error) {
	f, err := os.Open(filename, syscall.O_RDONLY, 666)
	if err != nil {
		return nil, utils.Error(fmt.Sprintf("failed to read file '%s'", filename), err)
	}

	return &FileReader{
		file: f,
		filename: filename,
		reader: bufio.NewReader(f),
	},
		nil
}

func (f *FileReader) ReadInt() (*big.Int, os.Error) {
	b, err := f.ReadLine()
	if err != nil {
		return nil, err
	}

	b = b[0 : len(b)-1]

	z := new(big.Int)
	_, ok := z.SetString(string(b), Base)
	if !ok {
		return nil, os.NewError("failed to convert conf value to hex string")
	}

	return z, nil
}

func (f *FileReader) ReadIntLen() (*big.Int, int, os.Error) {
	b, err := f.ReadLine()
	if err != nil {
		return nil, -1, err
	}

	b = b[0 : len(b)-1]

	z := new(big.Int)
	_, ok := z.SetString(string(b), Base)
	if !ok {
		return nil, -1, os.NewError("failed to convert conf value to hex string")
	}

	return z, len(b), nil

}

func (f *FileReader) ReadLine() ([]byte, os.Error) {
	b, err := f.reader.ReadBytes(NewLine)
	if err != nil {
		return nil, utils.Error("fauled to read bytes from file", err)
	}

	return b, nil
}

func (f *FileReader) CloseFile() os.Error {
	if err := f.file.Close(); err != nil {
		return utils.Error(fmt.Sprintf("failed to close file '%s'", f.filename), err)
	}

	return nil
}
