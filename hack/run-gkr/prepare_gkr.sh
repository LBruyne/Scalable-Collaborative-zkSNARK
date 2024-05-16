export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

source $HOME/.cargo/env
if ! which cargo &> /dev/null; then
    echo "Cargo is not installed. Running the script..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s - -y --default-toolchain nightly
    source $HOME/.cargo/env
else
    echo "Cargo is installed. Skipping the script."
fi

mkdir -vp ${CARGO_HOME:-$HOME/.cargo}
rm ${CARGO_HOME:-$HOME/.cargo}/config
cat << EOF | tee -a ${CARGO_HOME:-$HOME/.cargo}/config
[source.crates-io]
replace-with = 'ustc'

[source.ustc]
registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"
EOF

if ! which unzip &> /dev/null; then
    echo "unzip is not installed. Running the script..."
    sudo apt-get update
    sudo apt-get install unzip
else
    echo "unzip is installed. Skipping the script."
fi

unzip -o /tmp/gkr.zip -d /tmp/
rm /tmp/gkr.zip
cd /tmp/distributed-GKR

CARGO_HTTP_MULTIPLEXING=false RUSTFLAGS="-Awarnings" cargo +nightly build --release --example gkr