import argparse
import os 
import json
def file_exists(string):
    if os.path.isfile(string):
        return string
    else:
        raise FileNotFoundError(string)

def path_exists(string):
    if os.path.isdir(string):
        return string
    else:
        raise FileNotFoundError(string)

parser = argparse.ArgumentParser("run_client")
parser.add_argument("config", help="The config file", type=file_exists)
parser.add_argument("bin", help="The executable of client", type=file_exists)
parser.add_argument("input", help="Input of client", type=path_exists)
args = parser.parse_args()

config =  json.loads(open(args.config).read())

n_parties = config["l"]*4
print("Running {} parties".format(n_parties))

for i in range(n_parties):
    command = "RUST_LOG=info {} --id {} -c {} -i {} >{} 2>&1 &".format(args.bin, i, args.config, os.path.join(args.input, "worker_{}".format(i)), "worker_{}.log".format(i))
    print(command)
    os.system(command)