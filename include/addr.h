/*
 * Copyright (c) 2025, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef __RAW_U_ADDR_H
#define __RAW_U_ADDR_H

#include "include.h"

#define HAVE_UINT128	/* uint128_t est */

/*
 * LIBDNET STYLE
 * ipv4, ipv6, mac, cidr4,
 * cidr6
 */
typedef struct __addr_t {
#define AFIP4	AF_INET
#define AFIP6	AF_INET6
#define AFMAC	3
	int		af;		/* address family */
	union {
		u_char	ip4[4],		/* ipv4 address */
			ip6[16],	/* ipv6 address */
			mac[6];		/* mac address */
	} addr;
	struct {
		int	bits;		/* cidr bits ( /bits ) */
		u_char	mask[16],	/* cidr mask */
			broadcast[16],	/* cidr broadcast address */
			network[16];	/* cidr network address */
	} block;
} addr_t;

int	a_pton(addr_t *a, const char *cp);		/* convert str to addr_t */
int	a_ntop(addr_t *a, char *dst, size_t dstlen);	/* convert addr_t to str */
int	a_cmp(const addr_t *a, const addr_t *b);		/* a == b ?? */
char	*a_ntop_c(addr_t *a);				/* ntop but return static buffer */
#ifdef HAVE_UINT128
	int	a_cnth(addr_t *a, __uint128_t n, addr_t *dst);	/* return cidr[n] */
#else
	int	a_cnth(addr_t *a, size_t n, addr_t *dst);
#endif
int	a_bcast(const addr_t *a, addr_t *b);	/* get broadcast */
int	a_net(const addr_t *a, addr_t *b);	/* get network */
int	a_mask(const addr_t *a, addr_t *b);	/* get mask */

#endif
