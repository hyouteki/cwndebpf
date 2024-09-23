# kernel\_cwnd

An eBPF program that modifies the kernel's congestion window (cwnd) based on a user-space-provided value stored in an eBPF map. The modification occurs only if a fallback flag, stored in another eBPF map, is set to true. The user-space program updates these maps using the `bpftool map update` command.

## Getting Started
- `make`: Build `vmlinux.h` and the program.
- `make load_kernel_cwnd`: Attach the hooks and load the program.
- `make map.update MAP=CwndMap VAL=00`: Update the `CwndMap` for testing the loaded eBPF program.
- `make map.dump MAP=CwndMap`: Dump the contents of `CwndMap` to stdout.
- `make unload_kernel_cwnd`: Detach the hooks and unload the program.

# log\_tcp\_cwnd

An eBPF program that logs the kernel's congestion window (cwnd) value to the trace pipe whenever a TCP connection is used for an HTTPS request.

## Getting Started
- `make`: Build `vmlinux.h` and the program.
- `make load_log_tcp_cwnd`: Attach to the tracepoint and load the program.
- `make trace_log_tcp_cwnd`: Flush the trace pipe and store new logs in `log_tcp_cwnd.log`.
- `make log_tcp_cwnd.csv`: Process `log_tcp_cwnd.log` and create a CSV file.
- `make unload_log_tcp_cwnd`: Detach the hooks and unload the program.
- `make read_cwnd_map`: Demo to read the value of CwndMap in user-space program.

# always\_update\_cwnd

An eBPF program that modifies the kernel's congestion window (cwnd) based on a user-space-provided value stored in an eBPF map. Unlike `kernel_cwnd.bpf.c`, the update occurs every time. The user-space program updates these maps using the `bpftool map update` command.

## Getting Started
- `make`: Build `vmlinux.h` and the program.
- `make load_always_update_cwnd`: Attach the hooks and load the program.
- `make map.update MAP=CwndMap VAL=00`: Update the `CwndMap` for testing the loaded eBPF program.
- `make map.dump MAP=CwndMap`: Dump the contents of `CwndMap` to stdout.
- `make unload_always_update_cwnd`: Detach the hooks and unload the program.

> **Important**  
> Unloading the program is crucial; otherwise, the program and map will persist until the system restarts.

# Installation
```bash
git clone https://github.com/hyouteki/cwndebpf --depth=1
cd cwndebpf
make setup
git clone --recurse-submodules https://github.com/libbpf/bpftool
cd bpftool/src
make
```

## Dependency
- [libbpf-dev](https://packages.ubuntu.com/search?keywords=libbpf-dev)
- [bpftool](https://github.com/libbpf/bpftool)
- [Clang](https://clang.llvm.org/) and [LLVM](https://llvm.org/)

## References
- [Learning eBPF - lizrice](https://github.com/lizrice/learning-ebpf)
- [BPF helpers - man](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)