#!/bin/bash
set -e
utils="pkg/utils.go"
file="pkg/file.go"
oaep="pkg/oaep_c.go"
cmd="pkg/command.go"
attack="oaep/attack.go"

baseUtils="utils"
baseFile="file"
baseOaep="oaep_c"
baseCmd="command"
baseAttack="attack"

6g -o ${baseUtils}.6 $utils
6g -o ${baseFile}.6 $file
6g -o ${baseOaep}.6 $oaep
6g -o ${baseCmd}.6 $cmd
6g -o ${baseAttack}.6 $attack
6l -o oaep/${baseAttack} ${baseAttack}.6

rm ${baseUtils}.6
rm ${baseOaep}.6
rm ${baseFile}.6
rm ${baseCmd}.6
rm ${baseAttack}.6
