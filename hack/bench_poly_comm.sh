#!/bin/bash

for i in {18..30}
do
    just run --release -F leader --example poly_comm -- --l 32 --n $i > poly_comm_$i.txt
done