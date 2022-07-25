// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IP/TCP/UDP checksumming routines
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Tom May, <ftom@netcom.com>
 *		Andreas Schwab, <schwab@issan.informatik.uni-dortmund.de>
 *		Lots of code moved from tcp.c and ip.c; see those files
 *		for more names.
 *
 * 03/02/96	Jes Sorensen, Andreas Schwab, Roman Hodek:
 *		Fixed some nasty bugs, causing some horrible crashes.
 *		A: At some points, the sum (%0) was used as
 *		length-counter instead of the length counter
 *		(%1). Thanks to Roman Hodek for pointing this out.
 *		B: GCC seems to mess up if one uses too many
 *		data-registers to hold input values and one tries to
 *		specify d0 and d1 as scratch registers. Letting gcc
 *		choose these registers itself solves the problem.
 */

/* Revised by Kenneth Albanowski for m68knommu. Basic problem: unaligned access
 kills, so most of the assembly has to go. */

#ifndef DQDK_INET_CSUM_H
#define DQDK_INET_CSUM_H

#include <linux/types.h>
#include "../dqdk.h"

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
always_inline unsigned short from32to16(unsigned int x)
{
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
always_inline u32 from64to32(u64 x)
{
    /* add up 32-bit and 32-bit for 32+c bit */
    x = (x & 0xffffffff) + (x >> 32);
    /* add up carry.. */
    x = (x & 0xffffffff) + (x >> 32);
    return (u32)x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
always_inline unsigned int inet_csum(const unsigned char* buff, int len)
{
    unsigned int result = 0;
    int odd;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd) {
#ifdef __LITTLE_ENDIAN
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2) {
        if (2 & (unsigned long)buff) {
            result += *(unsigned short*)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4) {
            const unsigned char* end = buff + ((unsigned int)len & ~3);
            unsigned int carry = 0;

            do {
                unsigned int w = *(unsigned int*)buff;

                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2) {
            result += *(unsigned short*)buff;
            buff += 2;
        }
    }
    if (len & 1)
#ifdef __LITTLE_ENDIAN
        result += *buff;
#else
        result += (*buff << 8);
#endif
    result = from32to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
    return result;
}

always_inline __sum16 inet_fast_csum(const void* data, unsigned int size)
{
    return (__sum16)~inet_csum(data, size);
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
always_inline __sum16 ip_fast_csum(const void* iph, unsigned int ihl)
{
    return inet_fast_csum(iph, ihl * 4);
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
always_inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
    __u32 len, __u8 proto, __wsum sum)
{
    unsigned long long s = (u32)sum;

    s += (u32)saddr;
    s += (u32)daddr;
#ifdef __BIG_ENDIAN__
    s += proto + len;
#else
    s += (proto + len) << 8;
#endif
    return (__wsum)from64to32(s);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
always_inline __sum16 csum_fold(__wsum csum)
{
    u32 sum = (u32)csum;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__sum16)~sum;
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
always_inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
    __u8 proto, __wsum sum)
{
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

always_inline u16 udp_csum(u32 saddr, u32 daddr, u32 len,
    u8 proto, u16* udp_pkt)
{
    u32 csum = 0;
    u32 cnt = 0;

    /* udp hdr and data */
    for (; cnt < len; cnt += 2)
        csum += udp_pkt[cnt >> 1];

    return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

#endif
