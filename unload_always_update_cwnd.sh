#!/bin/bash
set -xe

BPFTOOL=/home/lakshay21060/bpftool/src/bpftool
if [ -f "/sys/fs/bpf/always_update_cwnd" ]; then
	sudo $BPFTOOL cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/always_update_cwnd
fi
sudo rm -f /sys/fs/bpf/always_update_cwnd /sys/fs/bpf/CwndMap /sys/fs/bpf/FallbackMap
