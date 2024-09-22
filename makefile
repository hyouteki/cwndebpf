BPFTOOL = /home/lakshay21060/bpftool/src/bpftool
VAL ?= 00
MAP ?= CwndMap

BPF_SOURCES = kernel_cwnd.bpf.c log_tcp_cwnd.bpf.c always_update_cwnd.bpf.c
BPF_OBJECTS = $(patsubst %.bpf.c, build/%.o, $(BPF_SOURCES))

default: $(BPF_OBJECTS)

./build/%.o: %.bpf.c vmlinux.h
	mkdir -p build
	clang \
		-target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g -O2 -c $< -o $@
	llvm-strip -g $@

vmlinux.h:
	sudo $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

load_kernel_cwnd: unload_kernel_cwnd
	sudo BPFTOOL=$(BPFTOOL) PROGRAM_NAME="kernel_cwnd" bash ./load_kernel_cwnd.sh

unload_kernel_cwnd:
	sudo BPFTOOL=$(BPFTOOL) PROGRAM_NAME="kernel_cwnd" bash ./unload_kernel_cwnd.sh

load_log_tcp_cwnd: unload_log_tcp_cwnd ./build/log_tcp_cwnd.o
	sudo $(BPFTOOL) prog load ./build/log_tcp_cwnd.o /sys/fs/bpf/log_tcp_cwnd autoattach

unload_log_tcp_cwnd:
	sudo BPFTOOL=$(BPFTOOL) bash ./unload_log_tcp_cwnd.sh

load_always_update_cwnd: unload_always_update_cwnd
	sudo BPFTOOL=$(BPFTOOL) PROGRAM_NAME="always_update_cwnd" bash ./load_kernel_cwnd.sh

unload_always_update_cwnd:
	sudo BPFTOOL=$(BPFTOOL) PROGRAM_NAME="always_update_cwnd" bash ./unload_kernel_cwnd.sh

logs:
	grep -rn "\[VOD-STREAM-QOE\]" /usr/local/lsws/logs/error.log

logs.clear:
	rm /usr/local/lsws/logs/error.log

map.update:
	sudo $(BPFTOOL) map update name $(MAP) key hex 00 00 00 00 value hex $(VAL) 00 00 00

map.dump:
	sudo $(BPFTOOL) map dump name $(MAP)

show:
	-sudo $(BPFTOOL) prog show name kernel_cwnd --pretty
	-sudo $(BPFTOOL) prog show name log_tcp_cwnd --pretty

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

trace_log_tcp_cwnd: trace_flush.sh
	chmod +x trace_flush.sh
	./trace_flush.sh
	sudo cat /sys/kernel/debug/tracing/trace_pipe > log_tcp_cwnd.log

log_tcp_cwnd.csv: process_cwnd_logs.py
	python3 process_cwnd_logs.py

setup:
	sudo apt-get update
	sudo apt-get install linux-headers-$(uname -r)
