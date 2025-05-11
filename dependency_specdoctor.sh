#!/bin/bash

set -ex

echo "[*] Installing dependencies for specdoctor"

# Install Python dependencies
pip3 install pyyaml psutil readerwriterlock Verilog_VCD

# Install RISC-V toolchain
sudo apt-get update
sudo apt-get install -y binutils-riscv64-unknown-elf gcc-riscv64-unknown-elf

# Install RISC-V ISA simulator if not already installed
if ! command -v spike &> /dev/null; then
    echo "Installing RISC-V ISA simulator (spike)"
    if [ -d "riscv-isa-sim" ]; then
        rm -rf riscv-isa-sim
    fi
    git clone https://github.com/riscv-software-src/riscv-isa-sim.git
    cd riscv-isa-sim
    mkdir -p build
    cd build
    ../configure
    make -j4
    sudo make install
    cd ../..
fi 