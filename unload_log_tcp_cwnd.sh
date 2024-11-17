#!/bin/bash
set -xe

if [ -z "${BPFTOOL}" ]; then
    echo "error: BPFTOOL is not set"
    exit 1
fi

if [ -f "/sys/fs/bpf/log_tcp_cwnd" ]; then
	sudo $BPFTOOL prog detach pinned /sys/fs/bpf/log_tcp_cwnd tracepoint
	rm -f /sys/fs/bpf/log_tcp_cwnd
fi

rm -f /sys/fs/bpf/CwndMap /sys/fs/bpf/SSThreshMap
