///////////////////////////////////////////////////////////
//                                                       //
//                 Joshua Van Leeuwen                    //
//                                                       //
//                University of Bristol                  //
//                                                       //
///////////////////////////////////////////////////////////

package time_c

import (
	"big"
	"os"

	"./utils"
	"./file"
)

type Conf struct {
	N *big.Int
	E *big.Int
}

// Initialise new Time Conf struct
func NewConf(fileName string) (*Conf, os.Error) {
	fr, err := file.NewFileReader(fileName)
	if err != nil {
		return nil, err
	}

	conf := new(Conf)

	if conf.N, err = fr.ReadInt(); err != nil {
		return nil, utils.Error("failed to get N", err)
	}

	if conf.E, err = fr.ReadInt(); err != nil {
		return nil, utils.Error("failed to get e", err)
	}

	return conf, nil
}
