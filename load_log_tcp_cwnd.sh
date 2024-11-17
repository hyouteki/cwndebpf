#!/bin/bash
set -xe

if [ -z "${BPFTOOL}" ]; then
    echo "error: BPFTOOL is not set"
    exit 1
fi

sudo BPFTOOL="${BPFTOOL}"  bash ./unload_log_tcp_cwnd.sh

sudo ${BPFTOOL} prog load ./build/log_tcp_cwnd.o /sys/fs/bpf/log_tcp_cwnd autoattach
sudo ${BPFTOOL} map pin name CwndMap /sys/fs/bpf/CwndMap
sudo ${BPFTOOL} map pin name SSThreshMap /sys/fs/bpf/SSThreshMap
