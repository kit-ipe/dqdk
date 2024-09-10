// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <xdp/xdp_helpers.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_SOCKS 16
#define MAX_PORTS 50

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u16 expected_udp_data_sz = 0;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_PORTS);
} control_ports SEC(".maps");

SEC("xdp/dqdk_forwarder")
int forward(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if (data >= data_end) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    if (data + ETH_HLEN >= data_end) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    struct ethhdr* eth = (struct ethhdr*)data;
    if (eth + 1 >= data_end) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_printk("XDP_PASS: %d\n", __LINE__);
        return XDP_PASS;
    }

    struct iphdr* ip = (struct iphdr*)(eth + 1);

    if (ip + 1 >= data_end) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_UDP) {
        bpf_printk("XDP_PASS: %d\n", __LINE__);
        return XDP_PASS;
    }

    struct udphdr* udp = (struct udphdr*)(ip + 1);
    if (udp + 1 >= data_end) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    int dstport = bpf_ntohs(udp->dest);
    int srcport = bpf_ntohs(udp->source);
    if (bpf_map_lookup_elem(&control_ports, &dstport) == NULL
        && bpf_map_lookup_elem(&control_ports, &srcport) == NULL) {
        bpf_printk("XDP_PASS: %d\n", __LINE__);
        return XDP_PASS;
    }

    // Sometimes it is control data but not using the control port?
    if (udp->len != expected_udp_data_sz) {
        bpf_printk("XDP_PASS: %d - UDP Len %d\n", __LINE__, bpf_ntohs(udp->len));
        return XDP_PASS;
    }

    // bpf_printk("SRC Port=%d | DST Port=%d\n", bpf_htons(udp->source), bpf_htons(udp->dest));

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}
