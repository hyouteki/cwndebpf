#!/bin/bash

BPFTOOL=/home/lakshay21060/bpftool/src/bpftool
if [ -f "/sys/fs/bpf/log_tcp_cwnd" ]; then
	sudo ${BPFTOOL} prog detach pinned /sys/fs/bpf/log_tcp_cwnd tracepoint
	rm -f /sys/fs/bpf/log_tcp_cwnd
fi
