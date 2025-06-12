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

#ifndef __RAW_U_UTILS_H
#define __RAW_U_UTILS_H

#include "include.h"
#include "err.h"

/* callback for recv: <frame> <frame len> <arg>*/
typedef u_char (*rcall_t)(u_char*,size_t,void*);
ssize_t frmrecv(int fd, u_char **buf, size_t buflen,
	void *arg, rcall_t callback, struct timeval *tstamp_s,
	struct timeval *tstamp_e, long long ns);

const char *timediff(struct timeval *s, struct timeval *e,
	char *out, size_t outlen);
const char *timefmt(long long ns, char *out, size_t outlen);
const char *strdate(char *out, size_t outlen);
char *resolve_ipv4(const char *hostname);
void nsdelay(long long ns);
long long delayconv(const char *txt);
void str_to_size_t(const char *str, size_t *out,
	size_t min, size_t max);
u_char *hex_ahtoh(char *txt, size_t *hexlen);

/* chksum */
u_short	ip4_pseudocheck(const u_char *src, const u_char *dst,
	u_char proto, u_short len, const void *hstart);

u_short ip6_pseudocheck(u_char *src, u_char *dst, u_char nxt,
	 u_int len, const void *hstart);

u_short	in_check(u_short *ptr, int nbytes);
u_int adler32(u_int adler, const u_char *buf, size_t len);

#endif
