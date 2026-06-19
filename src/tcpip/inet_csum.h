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
#include "ctypes.h"

#ifdef USE_SIMD
#include "inet_csum_simd.h"
#endif

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
dqdk_always_inline unsigned short from32to16(unsigned int x);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
dqdk_always_inline u32 from64to32(u64 x);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
dqdk_always_inline unsigned int inet_csum(const unsigned char* buff, int len);

dqdk_always_inline __sum16 inet_fast_csum(const void* data, unsigned int size);

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
dqdk_always_inline __sum16 ip_fast_csum(const void* iph, unsigned int ihl);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
dqdk_always_inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
    __u32 len, __u8 proto, __wsum sum);

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
dqdk_always_inline __sum16 csum_fold(__wsum csum);

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
dqdk_always_inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len, __u8 proto, __wsum sum);

dqdk_always_inline u16 udp_csum(u32 saddr, u32 daddr, u32 len, u8 proto, u16* udp_pkt);

#endif
