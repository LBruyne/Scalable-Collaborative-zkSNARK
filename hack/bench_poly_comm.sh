
#!/bin/bash

for i in {5..32}
do
    just run --release --example poly_comm -- --l 32 --width $i > poly_comm_$i.txt
done