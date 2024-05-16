#!/bin/bash

# Check if IP address file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <ip_address_file>"
    exit 1
fi

bash pack_zksaas.sh

# IP address file parameter
ip_address_file="$1"

# Create a temporary directory for log files
log_dir="."
for m in {20..32}; do
    index=0
    while read -r ip_address; do
        # Define the log file for each IP address
        log_file="$log_dir/log_${index}_${m}.txt"
        
        # Run the processes in parallel and redirect stdout to the log file
        (
            echo "Running on $ip_address with server_id $index"
            
            # SCP the zip file to the remote machine
            scp -o StrictHostKeyChecking=no zksaas.zip run_zksaas.sh prepare_zksaas.sh "root@$ip_address:/tmp/"
            
            # SSH into the remote machine and execute the script
            ssh -o StrictHostKeyChecking=no "root@$ip_address" "/bin/bash -s" <<EOF > "$log_file" 2>&1
            # Change to the directory where the zip file is located
            cd /tmp

            # Run the scripts
            bash ./prepare_zksaas.sh
            bash ./run_zksaas.sh $index $m

            # Exit the SSH session
            exit
EOF
        ) &
        
        ((index++))
    done < "$ip_address_file"
    
    # Wait for all background processes to finish
    wait
done
echo "All processes have completed. Log files are located in: $log_dir"