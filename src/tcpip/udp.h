#ifndef DQDK_IP4_UDP_H
#define DQDK_IP4_UDP_H

#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <limits.h>

#include "tcpip/ipv4.h"

#define udp_get_payload_size(frame, framelen) (framelen - (sizeof(struct ethhdr) + ip4_get_header_size((struct iphdr*)(frame + 1)) + sizeof(struct udphdr)))

#define UDP_PSUEDOIPHDR_LEN 10
#define UDP_HDR_LEN sizeof(struct udphdr)
#define UDP_MAXDATA_LEN SHRT_MAX
#define UDP_MAX_LEN (UDP_HDR_LEN + UDP_MAXDATA_LEN)

#define ETH_HDR_SIZE sizeof(struct ethhdr)
#define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_HDR_SIZE sizeof(struct ethhdr)
#define PKTGEN_HDR_SIZE sizeof(struct pktgen_hdr)
#define UDPIP_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + sizeof(struct udphdr))
#define PKT_HDR_SIZE (UDPIP_HDR_SIZE + PKTGEN_HDR_SIZE)

#define MIN_PKT_SIZE 64
#define PKT_SIZE (MIN_PKT_SIZE - ETH_FCS_LEN)
#define IP_PKT_SIZE (PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE (IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE (UDP_PKT_SIZE - (sizeof(struct udphdr) + PKTGEN_HDR_SIZE))

#define PKTGEN_MAGIC 0xbe9be955

struct pktgen_hdr {
    u32 pgh_magic;
    u32 seq_num;
    u64 ts_nano;
};

dqdk_always_inline int udp_audit_checksum(struct udphdr* udp, u32 src_ip, u32 dst_ip, u16 udplen);
dqdk_always_inline int udp_audit(struct udphdr* udp, u32 src_ip, u32 dst_ip, u16 udplen);
dqdk_always_inline void* memset32_htonl(void* dest, u32 val, u32 size);
dqdk_always_inline void udp_create_frame(u8* pkt_data, u8* daddr, u8* saddr, u16 pktsize);

#endif
