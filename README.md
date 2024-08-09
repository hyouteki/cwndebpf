## kernel\_cwnd
An eBPF program to modify the kernel's congestion window (cwnd) based on a user-space provided value stored in an eBPF map. The modification occurs only if a fallback flag, stored in another eBPF map, is set to true. The user-space program updates these maps using the `bpftool map update` command.

### Getting started
- `make`: build `vmlinux.h` and the program.
- `make load_kernel_cwnd.sh`: attach the hooks and load the program.
- `make map.update MAP=CwndMap VAL=00`: dummy user space program for testing the loaded eBPF program.
- `make map.dump MAP=CwndMap`: dump the contents of `CwndMap` onto the stdout.
- `make unload_kernel_cwnd.sh`: detach the hooks and unload the program.
> [!Important]
> Unloading the program is crucial; otherwise, the program and map will remain persistent until the system restarts.

## log\_tcp\_cwnd
An eBPF program to log the value of kernel congestion window (cwnd) to the trace pipe whenever a TCP connection is used for a HTTPS request.

### Getting started
- `make`: build `vmlinux.h` and the program.
- `make load_log_tcp_cwnd`: attach to the tracepoint and load the program.
- `make trace_log_tcp_cwnd`: flushes the trace\_pipe and stores new logs into `log_tcp_cwnd.log`
- `make log_tcp_cwnd.csv`: process the `log_tcp_cwnd.log` and creates a csv file.
- `make unload_log_tcp_cwnd.sh`: detach the hooks and unload the program.
> [!Important]
> Unloading the program is crucial; otherwise, the program and map will remain persistent until the system restarts.

## Dependency
- [libbpf-dev](https://packages.ubuntu.com/search?keywords=libbpf-dev)
- [bpftool](https://github.com/libbpf/bpftool)

## References
- [Learning eBPF - lizrice](https://github.com/lizrice/learning-ebpf)
- [BPF helpers - man](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
