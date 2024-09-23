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

if [ -f "/sys/fs/bpf/${PROGRAM_NAME}" ]; then
	sudo $BPFTOOL cgroup detach /sys/fs/cgroup/unified/ sock_ops pinned /sys/fs/bpf/${PROGRAM_NAME}
fi
sudo rm -f /sys/fs/bpf/${PROGRAM_NAME} /sys/fs/bpf/FallbackMap
