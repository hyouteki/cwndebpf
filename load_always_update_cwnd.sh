#!/bin/bash
set -xe

sudo mount -t bpf bpf /sys/fs/bpf/

sudo bash ./unload_always_update_cwnd.sh

BPFTOOL=/home/lakshay21060/bpftool/src/bpftool
sudo $BPFTOOL prog load ./build/always_update_cwnd.o /sys/fs/bpf/always_update_cwnd pinmaps /sys/fs/bpf/
sudo $BPFTOOL cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/always_update_cwnd
