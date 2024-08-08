/*
 * script to update congestion window using eBPF map
 * set value in map using bpftool map update
 */


/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set initial congestion window and initial receive
 * window to 40 packets and send and receive buffers to 1.5MB. This
 * would usually be done after doing appropriate checks that indicate
 * the hosts are far enough away (i.e. large RTT).
 *
 * Use "bpftool cgroup attach $cg sock_ops $prog" to load this BPF program.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define DEBUG 1
/*
 * Socket Operation Level TCP
 * from <netinet/tcp.h>
 */
#define SOL_TCP 6 

/*
 * TODO
 * update max_entries for both map from 1 to something like 1024*1024
 * when key is some combination of quic connection id and client id 
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} CwndMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} FallbackMap SEC(".maps");

SEC("sockops")
int kernel_cwnd(struct bpf_sock_ops *skops) {
	struct in_addr addr;
	// storing dest IPv4 for logging
	addr.s_addr = skops->remote_ip4;

	/*
	 * key: for client identification (currently the only value for key is zero)
	 * TODO: modify key to be a combination of client id & QUIC connection id  
	 * op: socket operation type
	 * *user_wnd: cwnd for that client (previously stored by the user space code)
	 * ret: return value
	 */
	int key = 0, val = 0, ret = 0, op, *userCwnd, *fallbackValue;

	op = (int) skops->op;
	// if op neither active nor passive TCP connection; skip
	if (op != 4 && op != 5) return 0;

#ifdef DEBUG
	bpf_printk("log: skops opcode %d", op);
#endif

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		fallbackValue = bpf_map_lookup_elem(&FallbackMap, &key);
		if (!fallbackValue) {
			// key not present in fallback map
			ret = bpf_map_update_elem(&FallbackMap, &key, &val, BPF_NOEXIST);
			if (!ret) bpf_printk("log: fallback value update to NOEXIST failed");
			break;
		}

		if (!*fallbackValue) {
			// fallback value is set to 0, false
			bpf_printk("log: fallback set to false, skipped cwnd updation");
			break;
		}
		
		// key present in fallback map
		userCwnd = bpf_map_lookup_elem(&CwndMap, &key);
		if (!userCwnd) {
			// key not present in cwnd map
			ret = bpf_map_update_elem(&CwndMap, &key, &val, BPF_NOEXIST);
			if (!ret) bpf_printk("log: cwnd value update to NOEXIST failed");
			break;
		}
		
		// key present in cwnd map
		if (!*userCwnd) return 0;
		// setting the initial congestion window to be same as `*userCwnd`
		ret = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, userCwnd, sizeof(int));
		if (!ret) bpf_printk("error %d: failed to set socket cwnd to %d", ret, *userCwnd);
		bpf_printk("log: set socket cwnd to %d for src IP &pI4", *userCwnd, &addr.s_addr);
		break;
	}

#ifdef DEBUG
	bpf_printk("log: return value %d", ret);
#endif

	// passing the return value back to the kernel
	skops->reply = ret;
	return 1;
}

char _license[] SEC("license") = "GPL";
