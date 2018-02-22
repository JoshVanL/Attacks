#!/bin/bash
set -e
export GOROOT=/home/josh/Work/AppliedSecurity/go2
export GOOS=linux
export GOARCH=amd64
baseOaep=$(basename ${1%\/*})
baseAttack=${2%\.*}
/home/josh/Work/AppliedSecurity/go2/bin/6g -o ${baseOaep}.6 "$1"
/home/josh/Work/AppliedSecurity/go2/bin/6g -o ${baseAttack}.6 "$2"
/home/josh/Work/AppliedSecurity/go2/bin/6l -o ${baseAttack} ${baseAttack}.6
rm ${baseOaep}.6
rm ${baseAttack}.6
