#!/bin/bash
set -e
utils="pkg/utils.go"
oaep="pkg/oaep.go"
attack="attack.go"

baseUtils="utils"
baseOaep="oaep"
baseAttack="attack"

6g -o ${baseUtils}.6 $utils
6g -o ${baseOaep}.6 $oaep
6g -o ${baseAttack}.6 $attack
6l -o ${baseAttack} ${baseAttack}.6

rm ${baseUtils}.6
rm ${baseOaep}.6
rm ${baseAttack}.6
