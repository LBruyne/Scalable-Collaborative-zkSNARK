#!/bin/bash

# Check if IP address file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <ip_address_file>"
    exit 1
fi

# bash pack.sh

# IP address file parameter
ip_address_file="$1"

while read -r ip_address; do
    # Define the log file for each IP address
    log_file="$log_dir/log_${index}_${m}_${l}.txt"
        
    # Run the processes in parallel and redirect stdout to the log file
    (
        scp -o StrictHostKeyChecking=no -i ~/.ssh/zkp.pem tmp.zip run.sh "root@$ip_address:/tmp/"
    ) &
        
    ((index++))
done < "$ip_address_file"
wait

# Create a temporary directory for log files
log_dir="./output"
for m in {24..24}; do
    for log_l in {4..6}; do
    l=$((2**$log_l))
    echo "Running m = $m and l = $l"
    index=0
    while read -r ip_address; do
        # Define the log file for each IP address
        log_file="$log_dir/log_${index}_${m}_${l}.txt"
        
        # Run the processes in parallel and redirect stdout to the log file
        (
            echo "Running on $ip_address with server_id $index"
            
            # SSH into the remote machine and execute the script
        ssh -o StrictHostKeyChecking=no -i ~/.ssh/zkp.pem "root@$ip_address" "/bin/bash -s" <<EOF > "$log_file" 2>&1
            # Change to the directory where the zip file is located
            cd /tmp

            # Run the scripts
            bash ./run.sh $index $m $l

            # Exit the SSH session
            exit
EOF
        ) &
        
        ((index++))
    done < "$ip_address_file"
    
    # Wait for all background processes to finish
    wait
    done
done
echo "All processes have completed. Log files are located in: $log_dir"