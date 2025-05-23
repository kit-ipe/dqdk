#ifndef DQDK_IP4_H
#define DQDK_IP4_H

#include <netinet/ip.h>

#include "../ctypes.h"
#include "tcpip/inet_csum.h"

#define ip4_get_header_size(hdr) (((struct iphdr*)hdr)->ihl * 4)

dqdk_always_inline int ip4_audit_checksum(struct iphdr* hdr)
{
    struct iphdr nhdr = *hdr;
    nhdr.check = 0;
    return ip_fast_csum(&nhdr, nhdr.ihl) == hdr->check;
}

dqdk_always_inline int ip4_audit(struct iphdr* hdr, u16 actual_pkt_len)
{
    u16 len = ntohs(hdr->tot_len);
    if (len != actual_pkt_len) // || !ip4_audit_checksum(hdr))
        return 0;

    return 1;
}

#endif
