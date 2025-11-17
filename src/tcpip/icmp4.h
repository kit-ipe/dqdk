#ifndef DQDK_IP4_ICMP_H
#define DQDK_IP4_ICMP_H

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "ctypes.h"
#include "tcpip/inet_csum.h"

dqdk_always_inline int icmp4_pong(struct ethhdr* frame, u32 len, u8* pong_reply);
void log_frame(struct ethhdr* frame);
void log_pingpong(struct iphdr* packet);
void log_icmp(u8* frame);

#endif
