#!/bin/bash

# This script flushes the trace_pipe

sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sudo echo > /sys/kernel/debug/tracing/trace
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on
