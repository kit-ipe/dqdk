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

#define bpf_unlikely(cond) __builtin_expect(!!(cond), 0)

#define MAX_SOCKS 16
#define MAX_PORTS 50

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__u8 debug = 0;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAX_PORTS);
} accept_ports SEC(".maps");

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md* ctx,
    __u64* timestamp) __ksym;

SEC("xdp")
int dqdk_forwarder(struct xdp_md* ctx)
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
    if (bpf_unlikely(eth + 1 >= data_end)) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    if (bpf_unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
        bpf_printk("XDP_PASS: %d\n", __LINE__);
        return XDP_PASS;
    }

    struct iphdr* ip = (struct iphdr*)(eth + 1);

    if (bpf_unlikely(ip + 1 >= data_end)) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    if (bpf_unlikely(ip->protocol != IPPROTO_UDP)) {
        bpf_printk("IP Protocol %d is not UDP\n", ip->protocol);
        return XDP_PASS;
    }

    struct udphdr* udp = (struct udphdr*)(ip + 1);
    if (bpf_unlikely(udp + 1 >= data_end)) {
        bpf_printk("XDP_DROP: %d\n", __LINE__);
        return XDP_DROP;
    }

    int srcport = bpf_ntohs(udp->source);
    if (bpf_map_lookup_elem(&accept_ports, &srcport) == NULL) {
        bpf_printk("XDP_PASS: %d\n", __LINE__);
        return XDP_PASS;
    }

    if (bpf_unlikely(debug)) {
        if (data + sizeof(__u64) < data_end) {
            int ret = bpf_xdp_metadata_rx_timestamp(ctx, (__u64*)data);
            if (ret < 0)
                bpf_printk("DQDK: bpf_xdp_metadata_rx_timestamp failed = %d\n", ret);
        }
    }

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}
