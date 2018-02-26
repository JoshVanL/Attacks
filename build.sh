#!/bin/bash
set -e

for f in "$@"
do
    filename=$(basename "$f")
    base="${filename%.*}"
    6g -o ${base}.6 $f
done

filename=${@:${#@}}
out="${filename%.*}"
filename=$(basename $filename)
base="${filename%.*}"
6l -o ${out} ${base}.6

for f in "$@"
do
    filename=$(basename "$f")
    base="${filename%.*}"
    rm ${base}.6
done
