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

#include "include/include.h"
#include "include/intf.h"
#include "include/cvector.h"
#include "include/utils.h"

struct timeval		_st,_et;	/* total time */

static inline void getopts(int c, char **av)
{
	int opt;
	if (c<=1) {
usage:
		puts("Usage");
		printf("  %s [-UsLCaeimt] [flags] <target target2 ...,>\n\n",av[0]);
		puts("  -N           no reverse DNS name resolution");

		/* set interface */
		puts("  -I <device>  set your interface and his info");
		/* interval */
		puts("  -i <time>    set interval between packets, ex: see down");
		/* timeout */
		puts("  -w <time>    set wait time or timeout, ex: 10s or 10ms");
		/* count */
		puts("  -n <count>   set num frames after stop");
		/* quit on first */
		puts("  -f           quit on first reply");
		/* cisco */
		puts("  -D           display line mode (! reply) (. noreply)");
		/* ttl */
		puts("  -t <ttl>     set your ttl/hop limit (Time To Live)");

		/* payload */
		puts("  -H <hex>     set payload data in hex numbers");
		puts("  -a <ascii>   set payload data in ascii");
		puts("  -l <length>  set random payload data");
		puts("  -h           show this help message and exit");
		putchar(0x0a);
		/* methods */
		puts("  -U  udp ping");
		puts("  -s  tcp syn ping");
		puts("  -a  tcp ack ping");
		puts("  -L  udp-lite ping");
		puts("  -e  icmp echo ping");
		puts("  -i  icmp info ping");
		puts("  -m  icmp mask ping");
		puts("  -t  icmp tstamp ping");
		puts("  -C  sctp cookie ping");
		/* help */

		puts("\nExamples");
		printf("  %s 192.168.1.1 -f -e localhost\n",av[0]);
		printf("  %s -G -i 300ms\n",av[0]);
		printf("  %s -G -v -n 1000 -i 10ms -0\n",av[0]);
		exit(0);
	}

	while ((opt=getopt(c,av,"h"))!=-1) {
		switch (opt) {
			case '?': case 'h': default:
				goto usage;
		}
	}
}

static inline noreturn void finish(int sig)
{
	(void)sig;
	gettimeofday(&_et,NULL);
	endmsg(&_st,&_et);
	exit(0);
}

int main(int c, char **av)
{
	signal(SIGINT,finish);
	gettimeofday(&_st,NULL);
	getopts(c,av);
	return 0;
}
