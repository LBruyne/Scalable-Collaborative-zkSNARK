#!/bin/bash

for i in {20..30}
do
    just run --release -F leader --example sumcheck -- --l 32 --n $i > sumcheck_$i.txt
done