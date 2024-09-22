#!/bin/bash
set -xe

if [ -z "${PROGRAM_NAME}" ]; then
    echo "error: PROGRAM_NAME is not set"
    exit 1
fi

if [ -z "${BPFTOOL}" ]; then
    echo "error: BPFTOOL is not set"
    exit 1
fi

sudo mount -t bpf bpf /sys/fs/bpf/

sudo BPFTOOL="${BPFTOOL}" PROGRAM_NAME="${PROGRAM_NAME}" bash ./unload_kernel_cwnd.sh

sudo $BPFTOOL prog load ./build/${PROGRAM_NAME}.o /sys/fs/bpf/${PROGRAM_NAME} pinmaps /sys/fs/bpf/
sudo $BPFTOOL cgroup attach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/${PROGRAM_NAME}
