#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define IP 0xA21DA8C0

SEC("tracepoint/tcp/tcp_probe")
int log_tcp_cwnd(struct trace_event_raw_tcp_probe *ctx) {

	u32 saddr, daddr;
	bpf_probe_read(&saddr, sizeof(saddr), &ctx->saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &ctx->daddr);

	// TCP packet is not of the desired connection
	if (saddr != IP && daddr != IP) {
		return 0;
	}

    u32 snd_cwnd = 0, snd_wnd = 0, rcv_wnd = 0;

    bpf_probe_read(&snd_cwnd, sizeof(snd_cwnd), &ctx->snd_cwnd);
    bpf_probe_read(&snd_wnd, sizeof(snd_wnd), &ctx->snd_wnd);
    bpf_probe_read(&rcv_wnd, sizeof(rcv_wnd), &ctx->rcv_wnd);

    bpf_printk("snd_cwnd: %d, snd_wnd: %d, rcv_wnd: %d\n", snd_cwnd, snd_wnd, rcv_wnd);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
