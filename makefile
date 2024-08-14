BPFTOOL = /home/lakshay21060/bpftool/src/bpftool
VAL ?= 00
MAP ?= CwndMap

default: ./build/kernel_cwnd.o ./build/log_tcp_cwnd.o
.PHONY: unload_kernel_cwnd.sh unload_log_tcp_cwnd.sh

./build/kernel_cwnd.o: kernel_cwnd.bpf.c vmlinux.h
	mkdir -p build
	clang \
		-target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g -O2 -c kernel_cwnd.bpf.c -o ./build/kernel_cwnd.o
	llvm-strip -g ./build/kernel_cwnd.o

./build/log_tcp_cwnd.o: log_tcp_cwnd.bpf.c vmlinux.h
	mkdir -p build
	clang \
		-target bpf \
			-D __TARGET_ARCH_$(ARCH) \
			-I/usr/include/$(shell uname -m)-linux-gnu \
			-g -O2 -c log_tcp_cwnd.bpf.c -o ./build/log_tcp_cwnd.o
	llvm-strip -g ./build/log_tcp_cwnd.o

./build/always_update_cwnd.o: always_update_cwnd.bpf.c vmlinux.h
	mkdir -p build
	clang \
		-target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g -O2 -c always_update_cwnd.bpf.c -o ./build/always_update_cwnd.o
	llvm-strip -g ./build/always_update_cwnd.o

vmlinux.h:
	sudo $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

load_kernel_cwnd.sh: unload_kernel_cwnd.sh
	sudo bash ./load_kernel_cwnd.sh

unload_kernel_cwnd.sh:
	sudo bash ./unload_kernel_cwnd.sh

load_log_tcp_cwnd: unload_log_tcp_cwnd.sh ./build/log_tcp_cwnd.o
	sudo $(BPFTOOL) prog load ./build/log_tcp_cwnd.o /sys/fs/bpf/log_tcp_cwnd autoattach

unload_log_tcp_cwnd.sh:
	sudo bash ./unload_log_tcp_cwnd.sh

load_always_update_cwnd.sh: unload_always_update_cwnd.sh
	sudo bash ./load_always_update_cwnd.sh

unload_always_update_cwnd.sh:
	sudo bash ./unload_always_update_cwnd.sh

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

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

trace_log_tcp_cwnd: trace_flush.sh
	chmod +x trace_flush.sh
	./trace_flush.sh
	sudo cat /sys/kernel/debug/tracing/trace_pipe > log_tcp_cwnd.log

log_tcp_cwnd.csv: process_cwnd_logs.py
	python3 process_cwnd_logs.py

setup:
	sudo apt-get update
	sudo apt-get install linux-headers-$(uname -r)
