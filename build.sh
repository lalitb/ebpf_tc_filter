#!/bin/bash
# Simple script to compile and load an eBPF TC "Hello World" program

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Configuration
INTERFACE="lo"  # Use loopback interface by default

# Compile the program
echo "Compiling hello_tc.c..."
clang -O2 -g -Wall -target bpf -c hello_tc.c -o hello_tc.o

# Check if compilation was successful
if [ ! -f "hello_tc.o" ]; then
    echo "Compilation failed!"
    exit 1
fi

# Clean up any existing qdisc
echo "Setting up TC..."
tc qdisc del dev $INTERFACE clsact 2>/dev/null
tc qdisc add dev $INTERFACE clsact

# Attach the program to the ingress hook
echo "Attaching eBPF program..."
tc filter add dev $INTERFACE ingress bpf direct-action obj hello_tc.o sec tc

# Show the attached filter
echo "Attached filter:"
tc filter show dev $INTERFACE ingress

# View the trace output
echo -e "\nReading trace pipe (press Ctrl+C to exit):"
echo "Generate some traffic by running 'ping 127.0.0.1' in another terminal"
cat /sys/kernel/debug/tracing/trace_pipe
