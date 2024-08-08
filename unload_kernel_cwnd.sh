#!/bin/bash

# This script detaches kernel_cwnd eBPF program from the cgroup
# and deletes the pinned kernel_cwnd program and eBPF maps

set -xe

if [ -f "/sys/fs/bpf/kernel_cwnd" ]; then
	sudo bpftool cgroup detach /sys/fs/cgroup/unified/kernel_cwnd sock_ops pinned /sys/fs/bpf/kernel_cwnd
fi
sudo rm -f /sys/fs/bpf/kernel_cwnd /sys/fs/bpf/CwndMap /sys/fs/bpf/FallbackMap
