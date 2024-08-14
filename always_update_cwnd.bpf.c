#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
	bpf_printk("log: skops opcode %d", op);
	// if op neither active nor passive TCP connection; skip
	if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) return 0;

	userCwnd = bpf_map_lookup_elem(&CwndMap, &key);
	if (!userCwnd) {
		// key not present in cwnd map
		ret = bpf_map_update_elem(&CwndMap, &key, &val, BPF_NOEXIST);
		if (ret != 0) bpf_printk("log: cwnd value update to NOEXIST failed");
		return 0;
	}
		
	// key present in cwnd map
	if (!*userCwnd) return 0;
	// setting the initial congestion window to be same as `*userCwnd`
	ret = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, userCwnd, sizeof(int));
	if (ret != 0) bpf_printk("error %d: failed to set socket cwnd to %d", ret, *userCwnd);
	else bpf_printk("log: set socket cwnd to %d for src IP %pI4", *userCwnd, &addr.s_addr);

	bpf_printk("log: return value %d", ret);
	// passing the return value back to the kernel
	skops->reply = ret;
	return 1;
}

char _license[] SEC("license") = "GPL";
