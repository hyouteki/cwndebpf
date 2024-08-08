#!/bin/bash
set -xe

sudo mount -t bpf bpf /sys/fs/bpf/
sudo mkdir -p /sys/fs/cgroup/unified/kernel_cwnd

./unload_kernel_cwnd.sh

sudo bpftool prog load ./build/kernel_cwnd.o /sys/fs/bpf/kernel_cwnd type sockops pinmaps /sys/fs/bpf/
sudo bpftool cgroup attach /sys/fs/cgroup/unified/kernel_cwnd sock_ops pinned /sys/fs/bpf/kernel_cwnd
