#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Socket Operation Level TCP
 * from <netinet/tcp.h>
 */
#define SOL_TCP 6

// TCP MSS
#define MSS 1460

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
} SSThreshMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} FallbackMap SEC(".maps");

int verify_remote_addr(__u32 remote_ip4) {
    unsigned char octets[4] = {
        (remote_ip4 >> 24) & 0xFF,
        (remote_ip4 >> 16) & 0xFF,
        (remote_ip4 >> 8) & 0xFF,
        remote_ip4 & 0xFF };

    unsigned char actual_remote_ip4[4] = {103, 25, 231, 106};

    for (size_t i = 0; i < 4; ++i) {
        if (octets[i] != actual_remote_ip4[i]) return 0;
    }

    return 1;
}

SEC("sockops")
int always_update_cwnd(struct bpf_sock_ops *skops) {
    struct in_addr addr;
    // storing dest IPv4 for logging
    addr.s_addr = skops->remote_ip4;

    // Will not update cwnd, if the machine is different from the experimentation machine
    // if (!verify_remote_addr(skops->local_ip4)) return 0;

    /*
     * key: for client identification (currently the only value for key is zero)
     * TODO: modify key to be a combination of client id & QUIC connection id
     * op: socket operation type
     * *user_wnd: cwnd for that client (previously stored by the user space code)
     * ret: return value
     */
    int key = 0, val = 0, ret = 0, op, *userCwnd, *fallbackValue, *userSSThresh;

    op = (int)skops->op;
    bpf_printk("log: skops opcode %d for src IP %pI4", op, &addr.s_addr);
    // if op neither active nor passive TCP connection; skip
    if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) return 0;

    userCwnd = bpf_map_lookup_elem(&CwndMap, &key);
    if (!userCwnd) {
        // key not present in cwnd map
        ret = bpf_map_update_elem(&CwndMap, &key, &val, BPF_NOEXIST);
        if (ret != 0) bpf_printk("log: CWND value update to NOEXIST failed");
        return 0;
    }

    // key present in cwnd map
    if (!*userCwnd) return 0;
    // *userCwnd = ceil(*userCwnd/MSS)
    int newCwnd = (unsigned long long)(*userCwnd+MSS-1)/(unsigned long long)MSS;
    bpf_printk("log: updating CWND to %d (%d MSS)", *userCwnd, newCwnd);
    *userCwnd = newCwnd;

    userSSThresh = bpf_map_lookup_elem(&SSThreshMap, &key);
    if (!userSSThresh) {
        // key not present in sshthresh map
        ret = bpf_map_update_elem(&SSThreshMap, &key, &val, BPF_NOEXIST);
        if (ret != 0) bpf_printk("log: SSThresh value update to NOEXIST failed");
        return 0;
    }

    // key present in ssthresh map
    if (!*userSSThresh) return 0;
    // *userSSThresh = ceil(*userSSThresh/MSS)
    int newSSThresh = (unsigned long long)(*userSSThresh+MSS-1)/(unsigned long long)MSS;
    bpf_printk("log: updating SSThresh to %d (%d MSS)", *userSSThresh, newSSThresh);
    *userSSThresh = newSSThresh;

    // setting the initial congestion window to be same as `*userCwnd`
    ret = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, userCwnd, sizeof(int));
    if (ret != 0) bpf_printk("error %d: failed to set socket CWND to %d", ret, *userCwnd);
    else bpf_printk("log: set socket CWND to %d", *userCwnd);

    // setting the slow start threshold to be same as `*userSSThresh`
    // Reference: https://netdevconf.info/2.2/papers/brakmo-tcpbpf-talk.pdf
    ret = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_SNDCWND_CLAMP, userSSThresh, sizeof(int));
    if (ret != 0) bpf_printk("error %d: failed to set socket SSThresh to %d", ret, *userSSThresh);
    else bpf_printk("log: set socket SSThresh to %d", *userSSThresh);

    bpf_printk("log: return value %d", ret);
    // passing the return value back to the kernel
    skops->reply = ret;
    return 1;
}

char _license[] SEC("license") = "GPL";
