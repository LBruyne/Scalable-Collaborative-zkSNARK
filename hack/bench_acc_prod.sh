#!/bin/bash

for i in {20..30}
do
    just run --release -F leader --example prod_acc -- --l 32 --n $i > prod_acc_$i.txt
done