#!/bin/bash

for j in {4,8,16,32}
do
    for i in {16..26}
    do
        # Run the hyperplonk example with varying server counts and circuit sizes
        just run --release -F local --example hyperplonk -- --l $j --n $i > ./output/hyperplonk_${j}_${i}.txt
    done
done