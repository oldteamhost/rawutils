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

static inline void getopts(int argc, char **argv)
{
	int opt;
	if (argc<=1) {
usage:
		puts("Usage");
		printf("  %s [flags] <target target1 ...,>\n\n",argv[0]);
		puts("  -I <device>  set your interface and his info");
		puts("  -n <count>   set num frames after stop");
		puts("  -i <time>    set interval between packets, ex: see down");
		puts("  -w <time>    set wait time or timeout, ex: 10s or 10ms");
		puts("  -H <hex>     set payload data in hex numbers");
		puts("  -a <ascii>   set payload data in ascii");
		puts("  -l <length>  set random payload data");
		puts("  -1           usage icmp ping");
		puts("  -L           usage udp-lite ping");
		puts("  -6           usage tcp ping");
		puts("  -U           usage udp ping");
		puts("  -N           no reverse DNS name resolution");

		/* ETHERNET II */
		puts("  -S <source>  set source custom MAC address		ETHERNET");
		puts("  -v <dest>    set dest custom MAC address		ETHERNET");
		puts("  -e <ptype>   set your payload type			ETHERNET");

		puts("  -Q <seq>     set your seq				ICMP TCP");
		puts("  -p <dstport> set your dest port 			TCP SCTP UDP UDPLITE");
		puts("  -9 <srcport> set your source port 			TCP SCTP UDP UDPLITE");
		puts("  -B           set invalid checksum 			ICMP TCP UDP UDPLITE SCTP");

		/* IPV4*/
		puts("  -O <hex>     set ipv4 options in send frames		IP4");
		puts("  -r           set Reserved Fragment flag		IP4");
		puts("  -s <source>  set source custom IP address		IP4");
		puts("  -o <tos>     set your num in field Type Of Service	IP4");
		puts("  -m <ttl>     set your Time To Live			IP4");
		puts("  -D <ident>   set your Identifier			IP4");
		puts("  -d           set Dont't Fragment flag			IP4");
		puts("  -4           set More Fragment flag			IP4");
		puts("  -b           set invalid checksum			IP4");

		/* TCP*/
		puts("  -P <hex>     set TCP options in send frames		TCP");
		puts("  -f <txt>     customize flags (S,A,P,F,R,C,P,U,E)	TCP");
		puts("  -A <ack>     set your ack number			TCP");
		puts("  -u <txt>     set your urgent pointer			TCP");
		puts("  -W <window>  set your window size			TCP");

		/* ICMP */
		puts("  -T <type>    set your icmp type			ICMP");
		puts("  -C <code>    set your icmp code (0)			ICMP");
		puts("  -7 <ident>   set your icmp ident			ICMP");

		/* SCTP */

		/* UDPLITE */
		puts("  -g <crg>     set your crg check			UDPLITE");
		puts("  -h           show this help message and exit");

		puts("\nExamples");
		printf("  %s 192.168.1.1 -f -e localhost\n",argv[0]);
		printf("  %s -G -i 300ms\n",argv[0]);
		printf("  %s -G -v -n 1000 -i 10ms -0\n",argv[0]);
		exit(0);
	}

	while ((opt=getopt(argc,argv,"h"))!=-1) {
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

int main(int argc, char **argv)
{
	signal(SIGINT,finish);
	gettimeofday(&_st,NULL);
	getopts(argc,argv);
	return 0;
}
