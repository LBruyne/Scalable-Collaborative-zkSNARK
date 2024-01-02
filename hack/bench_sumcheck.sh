
#!/bin/bash

for i in {5..32}
do
    just run --release --example sumcheck -- --l 32 --width $i > sumcheck_$i.txt
done