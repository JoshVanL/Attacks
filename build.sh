#!/bin/bash
set -e
baseOaep=$(basename ${1%\/*})
baseAttack=${2%\.*}
6g -o ${baseOaep}.6 "$1"
6g -o ${baseAttack}.6 "$2"
6l -o ${baseAttack} ${baseAttack}.6
rm ${baseOaep}.6
rm ${baseAttack}.6
