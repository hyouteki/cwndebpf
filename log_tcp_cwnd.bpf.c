#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#if Store_Cwnd
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
#endif

SEC("tracepoint/tcp/tcp_probe")
int log_tcp_cwnd(struct trace_event_raw_tcp_probe *ctx) {

	u16 sport, dport;
	bpf_probe_read(&sport, sizeof(sport), &ctx->sport);
	bpf_probe_read(&dport, sizeof(dport), &ctx->dport);

	// Protocol should be https
	if (sport != 443 && dport != 443) {
		return 0;
	}

    u32 snd_cwnd = 0, snd_wnd = 0, rcv_wnd = 0;
    bpf_probe_read(&snd_cwnd, sizeof(snd_cwnd), &ctx->snd_cwnd);
    bpf_probe_read(&snd_wnd, sizeof(snd_wnd), &ctx->snd_wnd);
    bpf_probe_read(&rcv_wnd, sizeof(rcv_wnd), &ctx->rcv_wnd);

    bpf_printk("snd_cwnd: %d, snd_wnd: %d, rcv_wnd: %d\n", snd_cwnd, snd_wnd, rcv_wnd);

#if Store_Cwnd
    u32 key = 0;
    int ret = bpf_map_update_elem(&CwndMap, &key, &snd_wnd, BPF_ANY);
	if (ret != 0) bpf_printk("log: cwnd value update to '%d' failed", snd_wnd);
#endif

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
