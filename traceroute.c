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
#include "include/random.h"
#include "include/utils.h"
#include "include/addr.h"

typedef struct __cidr_block_t
{
	cvector(addr_t)	raw;	/* cidrs */
#ifdef HAVE_UINT128
	__uint128_t	cur;	/* current */
	__uint128_t	curpos;	/* current position on cidr  */
#else
	size_t		cur;	/* current */
	size_t		curpos;	/* current position on cidr */
#endif
} cidr_block_t;

cidr_block_t		block[2];	/* cird target [0]=ipv4 [1]=ipv6*/
cvector(addr_t)		targets=NULL;	/* cvector_vector_type */
struct timeval		_st,_et;	/* total time */
u_char			Iflag=0;
intf_t			i={0};
int			mttl=30,ttl=1;	/* max ttl and ttl */
addr_t			sopt;
u_char			*buffer=NULL;	/* for recv() */
u_char			printstats=0;	/* print last stats ? */
addr_t			curtarget;	/* last target (current) */
long long		wait=150*1000000LL;	/* timeout 150 ms */
long long		interval=0;	/* delay */
u_char			sflag=0;
struct timeval		tstamp_s,tstamp_e;	/* for rtt */
u_char			Sflag=0;
addr_t			Sopt;
char			*data=NULL;	/* payload */
size_t			datalen=0;
u_char			oflag=0;
size_t			nreceived=0,ntransmitted=0;
long long		tsum=0,tmin=LLONG_MAX,tmax=LLONG_MIN;
size_t			try=3;	/* count try */
u_char			oopt=0;
int			method=IPPROTO_ICMP;	/* method traceroute */
u_char			all=0;	/* all methods */
u_char			reached=0;	/* aee */
int			off=0;
u_char			reply_state=0;	/* last recv status */
int			fd=-1;
int			hop=0;	/* current hop */
u_char			Pflag=0;
u_short			lastipid=0;	/* for filter */
u_short			Popt=0;
u_char			pflag=0;
addr_t			source;		/* check traceroutecallback() */
u_short			popt=0;
long long		*rtts=NULL;	/* times free() */
u_char			_6flag=0;
addr_t			_6opt;

static inline u_char *tracerouteframe(u_int *outlen, addr_t *target,
	 int proto, u_char *_data, u_int _datalen)
{
	u_char	*frame;	/* result frame (packet) */
	int	n,s;	/* counter */

	assert(proto);
	assert(outlen);
	assert(target);

	/* only ipv4 or ipv6 */
	assert(target->af==AF_INET||target->af==AF_INET6);

	*outlen=0;
	*outlen+=14;		/* ethernet 2 */
	*outlen+=20;		/* ipv4 */
	if (target->af==AF_INET6) {
		*outlen+=20;		/* ipv6 (40) */
		proto=(proto==IPPROTO_ICMP)?	/* fix proto */
			IPPROTO_ICMPV6:proto;
	}
	s=(int)*outlen;	/* this skip ad payload */
	switch (proto) {
		case IPPROTO_TCP:
			*outlen+=20;
			break;
		case IPPROTO_SCTP:
			*outlen+=16;	/* sctp + cookie chunk */
			break;
		case IPPROTO_ICMP:	/* icmp + echo msg (valid for ipv6) */
		case IPPROTO_ICMPV6:
		case IPPROTO_UDPLITE:
		case IPPROTO_UDP:
			*outlen+=8;
			break;
	}
	*outlen+=_datalen;

	if (!(frame=calloc(1,*outlen)))
		errx(1,"failed allocated frame (%ld len)",*outlen);
	lastipid=random_u16(),hop=ttl;

	/* ETHERNET 2 */
	memcpy(frame,i.dstmac,6);				/* dst mac */
	memcpy(frame+6,i.srcmac,6);				/* src mac */
	*(u_short*)(void*)(frame+12)=(target->af==AF_INET)?
			htons(0x0800):htons(0x86DD);		/* ip4/ip6 payload */

	/* IP4 / IP6 */
	switch (target->af) {
		case AF_INET:
			frame[14]=(4<<4)|5/*5+(optslen/4)*/;			/* version|ihl */
			frame[15]=(oflag)?oopt:0;				/* tos */
			*(u_short*)(void*)(frame+16)=htons((u_short)		/* tot_len +optslen */
				(*outlen-14));
			*(u_short*)(void*)(frame+18)=htons(lastipid);		/* id */
			*(u_short*)(void*)(frame+20)=htons((u_short)off);	/* off */
			frame[22]=(u_char)ttl;					/* ttl */
			frame[23]=(u_char)proto;				/* proto */
			*(u_short*)(void*)(frame+24)=0;				/* chksum */
			for(n=0;n<4;n++)
				frame[26+n]=i.srcip4[n],	/* via in caelum */
					frame[30+n]=target->addr.ip4[n];
			/*
			 * old verison
			 * for(n=0;n<4;n++)
			 * 	frame[26+n]=i.srcip4[n], via in caelum
			 * 		frame[30+n]=(ntohl(target->ip4)>>(24-8*n))&0xff;
			 */
			*(u_short*)(void*)(frame+24)=in_check((u_short*)(void*)(frame+14),20);
			break;
		case AF_INET6:
			frame[14]=((0x06<<4)|((((oflag)?oopt:0)&0xF0)>>4));			/* version|tc */
			frame[15]=(u_char)(((((oflag)?oopt:0)&0x0F)<<4)|			/* flowlabel */
					((lastipid&0xF0000)>>16));
			frame[16]=((lastipid&0x0FF00)>>8),frame[17]=((lastipid&0x000FF));
			*(u_short*)(void*)(frame+18)=htons((u_short)*outlen-(54));		/* payload length */
			frame[20]=(u_char)proto;						/* nexthdr (protocol) */
			frame[21]=(u_char)ttl;							/* hoplimit (ttl) */
			for(n=0;n<16;n++)					/* src+dst */
				frame[22+n]=i.srcip6[n],
					frame[22+16+n]=target->addr.ip6[n];
			break;
	}

	/* PAYLOAD IP */
	switch (proto) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			frame[s]=(proto==IPPROTO_ICMPV6)?128:8;			/* type */
			frame[s+1]=0;						/* code */
			*(u_short*)(void*)(frame+s+2)=htons(0);			/* chksum */
			*(u_short*)(void*)(frame+s+4)=htons(random_u16());	/* id */
			*(u_short*)(void*)(frame+s+6)=htons(1);			/* seq */

			if (_data&&_datalen)
			    memcpy(frame+s+8,_data,_datalen);

			switch (target->af) {
				case AF_INET:
					*(u_short*)(void*)(frame+s+2)=in_check((u_short*)
						(void*)(frame+s),(int)(8+_datalen));
					break;
				case AF_INET6:
					*(u_short*)(void*)(frame+s+2)=ip6_pseudocheck(i.srcip6,
						target->addr.ip6,IPPROTO_ICMPV6,(u_int)(8+_datalen),
						(frame+s));
					break;
			}

			break;
		case IPPROTO_TCP:
			*(u_short*)(void*)(frame+s)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+s+2)=(pflag)?htons(popt):htons(80);		/* dst port */
			memcpy(frame+s+4,&(u_int){htonl(random_u32())},sizeof(u_int));		/* seq */
			memcpy(frame+s+8,&(u_int){htonl(0)},sizeof(u_int));			/* ack */
			frame[s+12]=(5<<4)|(0&0x0f);						/* off | res */
			frame[s+13]=2;								/* flags */
			*(u_short*)(void*)(frame+s+14)=htons(1024);				/* window */
			*(u_short*)(void*)(frame+s+16)=0;					/* chksum */
			*(u_short*)(void*)(frame+s+18)=0;					/* urp */

			if(_data&&_datalen)
				memcpy(frame+s+20,_data,_datalen);

			switch (target->af) {
				case AF_INET:
					*(u_short*)(void*)(frame+s+16)=ip4_pseudocheck(i.srcip4,
						target->addr.ip4,(u_char)proto,(20+(u_short)_datalen),
						(frame+s));
					break;
				case AF_INET6:
					*(u_short*)(void*)(frame+s+16)=ip6_pseudocheck(i.srcip6,
						target->addr.ip6,(u_char)proto,(u_int)(20+_datalen),
						(frame+s));
					break;
			}

			break;
		case IPPROTO_SCTP:
			*(u_short*)(void*)(frame+s)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+s+2)=(pflag)?htons(popt):htons(80);		/* dst port */
			*(u_int*)(void*)(frame+s+4)=htonl(random_u32());			/* vtag */
			*(u_int*)(void*)(frame+s+8)=htonl(0);					/* chksum */
			frame[s+12]=0x0a;							/* type */
			frame[s+13]=0;								/* flags */
			*(u_short*)(void*)(frame+s+14)=htons(4+(u_short)_datalen);		/* len */

			if(_data&&_datalen)
				memcpy(frame+s+16,_data,_datalen);

			*(u_int*)(void*)(frame+s+8)=htonl(adler32(1,(frame+s)			/* final chksum */
					,16+_datalen));
			break;
		case IPPROTO_UDP:
			*(u_short*)(void*)(frame+s)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+s+2)=(pflag)?htons(popt):htons(80);		/* dst port */
			*(u_short*)(void*)(frame+s+4)=htons(8+(u_short)_datalen);		/* len */
			*(u_short*)(void*)(frame+s+6)=htons(0);					/* chksum */

			if(_data&&_datalen)
				memcpy(frame+s+8,_data,_datalen);

			switch (target->af) {
				case AF_INET:
					*(u_short*)(void*)(frame+s+6)=ip4_pseudocheck(i.srcip4,
						target->addr.ip4,(u_char)proto,(8+(u_short)_datalen),
						(frame+s));
					break;
				case AF_INET6:
					*(u_short*)(void*)(frame+s+6)=ip6_pseudocheck(i.srcip6,
						target->addr.ip6,(u_char)proto,(u_int)(8+_datalen),
						(frame+s));
					break;
			}

			break;
		case IPPROTO_UDPLITE:
			*(u_short*)(void*)(frame+s)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+s+2)=(pflag)?htons(popt):htons(80);           	/* dst port */
			*(u_short*)(void*)(frame+s+4)=htons(0);                                 /* checkcrg */
			*(u_short*)(void*)(frame+s+6)=htons(0);                                 /* chksum */

			if (_data&&_datalen)
				memcpy(frame+s+8,_data,_datalen);

			switch (target->af) {
				case AF_INET:
					*(u_short*)(void*)(frame+s+6)=ip4_pseudocheck(i.srcip4,
						target->addr.ip4,(u_char)proto,(8+(u_short)_datalen),
						(frame+s));
					break;
				case AF_INET6:
					*(u_short*)(void*)(frame+s+6)=ip6_pseudocheck(i.srcip6,
						target->addr.ip6,(u_char)proto,(u_int)(8+_datalen),
						(frame+s));
					break;
			}

			break;
	}

	return frame;
}

static inline void stats(addr_t *target)
{
	char t1[1000],t2[1000],t3[1000];
	
	printf("\n----%s TRACEROUTE Statistics----\n",a_ntop_c(target));
	printf("%ld packets transmitted, %ld packets received",
		ntransmitted,nreceived);
	if (nreceived>ntransmitted)
		printf(" -- somebody's printing up packets!\n");
	else
		printf(", %ld%% packet loss\n",(size_t)
			(((ntransmitted-nreceived)*100)/ntransmitted));
	if (nreceived)
		printf("round-trip (rtt) min/avg/max = %s/%s/%s\n",
			timefmt(tmin,t1,sizeof(t1)),
			timefmt((long long)tsum/(long long)nreceived,t2,sizeof(t2)),
			timefmt(tmax,t3,sizeof(t3)));
	printf("target %s %s %d hops\n",a_ntop_c(target),(reached)?"was reached in":
		"has been missed for",hop);

	putchar(0x0a);
}

static inline noreturn void finish(int sig)
{
	(void)sig;
	
	if (!printstats)
		stats(&curtarget);
	gettimeofday(&_et,NULL);
	endmsg(&_st,&_et);

	if (fd>=0)	/* socket */
		close(fd);
	if (rtts)	/* times */
		free(rtts);
	if (buffer)
		free(buffer);
	if (data)
		free(data);
	if (targets)
		cvector_free(targets);	/* targets */
	if (block[0].raw)
		cvector_free(block[0].raw);	/* cidrs */
	if (block[1].raw)
		cvector_free(block[1].raw);	/* cidrs ipv6 */
	if (nreceived)
		exit(0);
	else
		exit(1);
}


static inline void getopts(int argc, char **argv)
{
	const char		*ip;
	int			opt,n;
	size_t			numtmp;
	u_char			*hextmp;
	addr_t			addr;

	if (argc<=1) {
usage:
		puts("Usage");
		printf("  %s [options] <targets>\n\n",argv[0]);
		puts("  I <device>  set your interface and his info");
		puts("  s <source>  set source custom IP4 address");
		puts("  6 <source>  set source custom IPV6 address");
		puts("  n <count>   set your num of try");
		puts("  S <source>  set source custom MAC address");
		puts("  o <tos>     set num in Type Of Service/Traffic class");
		puts("  P <port>    set source (your) port");
		puts("  m <ttl>     set max ttl/hop limit (num hops)");
		puts("  i <time>    set interval between packets, ex: see down");
		puts("  w <time>    set wait time or timeout, ex: 10s or 10ms");
		puts("  f <ttl>     set first ttl/hop limit (start hop)");
		puts("  p <port>    set destination port");
		puts("  H <hex>     set payload data in hex numbers");
		puts("  a <ascii>   set payload data in ascii");
		puts("  l <length>  set random payload data");
		putchar(0x0a);
		puts("  A  use all methods and protos");
		puts("  E  use only icmp4 echo packets");
		puts("  Y  use only tcp syn packets");
		puts("  U  use only udp packets");
		puts("  L  use only udp-lite packets");
		puts("  C  use only sctp-cookie packets");
		puts("  r  set Reserved Fragment flag (ipv4)");
		puts("  d  set Dont't Fragment flag (ipv4)");
		puts("  4  set More Fragment flag (ipv4)");
		puts("  h  show this help message and exit");
		puts("\nExamples");
		printf("  %s google.com -A\n",argv[0]);
		printf("  %s 5.255.255.77 -n 10 -w 50ms\n",argv[0]);
		printf("  %s github.com 5.255.255.77 -n 10 -A\n",argv[0]);
		exit(0);
	}

	while ((opt=getopt(argc,argv,"hI:s:S:o:P:p:H:a:l:dr4m:f:n:w:AEYULCi:6:"))!=-1) {
		switch (opt) {
			case 'A':
				all=1;
				break;
			case 'i':
				if ((interval=delayconv(optarg))==-1)
					errx(1,"failed convert %s time",
						optarg);
				break;
			case 'E':
				method=IPPROTO_ICMP;
				break;
			case 'Y':
				method=IPPROTO_TCP;
				break;
			case 'U':
				method=IPPROTO_UDP;
				break;
			case 'L':
				method=IPPROTO_UDPLITE;
				break;
			case 'C':
				method=IPPROTO_SCTP;
				break;
			case 'I':
				++Iflag;
				intfget(&i,optarg);
				/* check in main() */
				break;
			case 'f':
				str_to_size_t(optarg,&numtmp,1,USHRT_MAX);
				ttl=(int)numtmp;
				break;
			case 'm':
				str_to_size_t(optarg,&numtmp,1,USHRT_MAX);
				mttl=(int)numtmp;
				break;
			case 'd':
				off|=0x4000;
				break;
			case 'w':
				if ((wait=delayconv(optarg))==-1)
					errx(1,"failed convert %s time",
						optarg);
				break;
			case 'r':
				off|=0x8000;
				break;
			case '4':
				off|=0x2000;
				break;
			case 'n':
				str_to_size_t(optarg,&numtmp,1,UINT_MAX);
				try=numtmp;
				break;
			case 's':
				if ((a_pton(&sopt,optarg))==-1)
					errx(1,"failed convert \"%s\" this",
						optarg);
				if (sopt.af!=AFIP4)
					errx(1,"support only IPv4 address \"%s\"",
						optarg);
				++sflag;
				break;
			case '6':
				if ((a_pton(&_6opt,optarg))==-1)
					errx(1,"failed convert \"%s\" this",
						optarg);
				if (_6opt.af!=AFIP6)
					errx(1,"support only IPv6 address \"%s\"",
						optarg);
				++_6flag;
				break;
			case 'o':
				str_to_size_t(optarg,&numtmp,0,UCHAR_MAX);
				oopt=(u_char)numtmp;
				++oflag;
				break;
			case 'H':
				hextmp=hex_ahtoh(optarg, &datalen);
				if (!hextmp)
					errx(1, "invalid hex string specification");
				if (!(data=memcpy(calloc(1,datalen),hextmp,datalen)))
					errx(1, "memory allocation failed");
				break;
			case 'a':
				data=strdup(optarg);
				if (!data)
					errx(1,"failed allocated");
				datalen=strlen(data);
				break;
			case 'l':
				str_to_size_t(optarg,&numtmp,0,UINT_MAX);
				datalen=numtmp;
				data=random_str(datalen,DEFAULT_DICTIONARY);
				if (!data)
					errx(1,"failed generate random data");
				break;
			case 'p':
			case 'P':
				str_to_size_t(optarg,&numtmp,1,USHRT_MAX);
				if (opt=='P') {
					Popt=(u_short)numtmp;
					++Pflag;
				}
				else {
					popt=(u_short)numtmp;
					++pflag;
				}
				break;
			case 'S':
				if ((a_pton(&Sopt,optarg))==-1)
					errx(1,"failed convert \"%s\" mac address",
						optarg);
				if (Sopt.af!=AFMAC)
					errx(1,"is not MAC address \"%s\"",
						optarg);
				++Sflag;
				break;
			case '?': case 'h': default:
				goto usage;
		}
	}
	n=argc-optind;
	if (n<=0)
		goto usage;

	block[0].cur=block[1].cur=0;
	block[0].curpos=block[1].curpos=0;

	for (n=optind;n<argc;n++) {
		memset(&addr,0,sizeof(addr));
		addr.block.bits=-1;

		if ((a_pton(&addr,argv[n]))!=0) {
			/* ok, this dns or fucking error? */
			if (!(ip=resolve_ipv4(argv[n])))
				errx(1,"failed resolution \"%s\" name",argv[n]);
			assert((a_pton(&addr,ip))!=-1);
		}
		switch (addr.af) {
			case AFMAC:
				errx(1,"not support MAC address \"%s\"",argv[n]);
			default:
				break;
		}
		if (addr.block.bits!=-1) {
			if (addr.af==AF_INET6)
				cvector_push_back(block[1].raw,addr);
			else
				cvector_push_back(block[0].raw,addr);
		}
		else
			cvector_push_back(targets,addr);
	}
}

static inline u_char traceroutecallback(u_char *frame, size_t frmlen, void *arg)
{
	/* arg is target */
	addr_t *target=(addr_t*)arg;

	source.block.bits=-1;
	switch (target->af) {
		case AF_INET:
			source.af=AFIP4;
			if (frmlen<42)	/* eth + ip + icmp */
				return 0;
			/* only ip frames */
			if (ntohs(*(u_short*)(void*)(frame+12))!=0x0800)
				return 0;
			/* check ip src in first ip header */
			if (!(memcmp((frame+26),target->addr.ip4,4))) {
				memcpy(&source.addr.ip4,(frame+26),4);
				/* reached */
				reached=1;
				return (reply_state=1);
			}
			if (frame[23]!=IPPROTO_ICMP)	/* only icmp packets */
				return 0;
			if (frame[34]!=11)	/* time exceed */
				return 0;
			if (memcmp((frame+30),i.srcip4,4)!=0)	/* ip dst */
				return 0;
			memcpy(&source.addr.ip4,(frame+26),4);
			/* check ipid in second ip header */
			if (ntohs((*(u_short*)(void*)(frame+42+4)))!=lastipid)
				return 0;
			break;
		case AF_INET6:
			source.af=AFIP6;
			if (frmlen<54)	/* eth ipv6 icmp */
				return 0;
			/* only ip6 frames */
			if (ntohs(*(u_short*)(void*)(frame+12))!=0x86dd)
				return 0;
			if (!memcmp((frame+22),target->addr.ip6,16)) {
				memcpy(source.addr.ip6,(frame+22),16);
				/* reached */
				reached=1;
				return (reply_state=1);
			}
			if (frame[20]!=IPPROTO_ICMPV6)	/* only icmp6 packets */
				return 0;
			if (frame[54]!=3)	/* time exceed */
				return 0;
			if (memcmp((frame+38),i.srcip6,16)!=0)	/* ip dst */
				return 0;
			memcpy(source.addr.ip6,(frame+22),16);
			/* check flowlabel in second ipv6 */
			const u_int *inner_ipv6_hdr=(const u_int*)(void*)(frame+62);
			u_int flowlabel=ntohl(inner_ipv6_hdr[0])&0x000FFFFF;
			if (flowlabel!=lastipid)
				return 0;
			break;
	}

	/* aee */
	reply_state=1;
	return 1;
}

static inline const char *resolve_dns(addr_t *t)
{
	static char res[2048+2];
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa4;
	char dnsbuf[2048];

	memset(dnsbuf,0,sizeof(dnsbuf));

	switch (t->af) {
		case AF_INET:
			memset(&sa4,0,sizeof(sa4));
			sa4.sin_family=(u_short)t->af;
			memcpy(&sa4.sin_addr.s_addr,t->addr.ip4,4);
			if (getnameinfo((struct sockaddr*)&sa4,sizeof(sa4),
					dnsbuf,sizeof(dnsbuf),NULL,0,0)==0) {
				snprintf(res,sizeof(res),"(%s)",dnsbuf);
				return res;
			}
			break;
		case AF_INET6:
			memset(&sa6,0,sizeof(sa6));
			sa6.sin6_family=(u_short)t->af;
			memcpy(&sa6.sin6_addr,t->addr.ip6,16);
			if (getnameinfo((struct sockaddr*)&sa6,sizeof(sa6),
					dnsbuf,sizeof(dnsbuf),
					NULL,0,0)==0) {
				snprintf(res,sizeof(res),"(%s)",dnsbuf);
				return res;
			}
			break;
	}

	return "(\?\?\?)";
}

static inline int importcidr(cidr_block_t *c)
{
	addr_t host;
	size_t n;

	/* cidr end */
	if ((c->cur)>=cvector_size(c->raw))
		return 0;	/* close */

	for (n=0;n<30;n++) {	/* group 30 targets */
		if ((a_cnth(&c->raw[c->cur],
				(n+c->curpos),&host))==-1) {	/* is last */
			++c->cur;
			c->curpos=0;
			return 1;
		}
		cvector_push_back(targets,host);	/* add to targets */
	}

	c->curpos+=n;	/* save current pos in current cidr in block*/
	return 1;
}

static inline long long tvrtt(struct timeval *s, struct timeval *e)
{
	long long sec,usec,rtt;

	sec=e->tv_sec-s->tv_sec;
	usec=e->tv_usec-s->tv_usec;

	/* fix time */
	if (usec<0) {
		sec-=1;
		usec+=1000000;
	}

	rtt=(long long)sec*1000000000LL+
		(long long)usec*1000LL;

	tsum+=rtt;	/* update stats */
	tmax=(rtt>tmax)?rtt:tmax;
	tmin=(rtt<tmin)?rtt:tmin;

	return rtt;
}

int main(int argc, char **argv)
{
	struct sockaddr_ll		sll={0};
	u_char				*frame=NULL;
	u_int				len=0;
	cvector_iterator(addr_t)	it=NULL;
	size_t				hopid=1,j=0;
	u_char				ok=0,p=0;
	addr_t				tmpip;
	u_char				success=0;
	char				time[1000];
	int				tot=0,first=0;

	random_set(0);	/* random init */
	Srandom(random_seed_u64());

	signal(SIGINT,finish);
	gettimeofday(&_st,NULL);
	getopts(argc,argv);

	if (!Iflag)
		intfget_any(&i);
	else if (!intf_is_network_sendable(&i))
		errx(1,"this interface doesn't fit");
	if (sflag)	/* src your*/
		memcpy(i.srcip4,sopt.addr.ip4,4);
	if (_6flag)	/* src6 your*/
		memcpy(i.srcip6,_6opt.addr.ip6,16);
	if (Sflag)	/* srcmac your */
		memcpy(i.srcmac,Sopt.addr.mac,6);
	if (datalen>(size_t)i.mtu-100)
		errx(1, "your mtu-100 is (%ld), your length"
			" data is \"%d\"",i.mtu-100,datalen);
	isroot();
	if ((fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
		errx(1,"failed create socket");
	sll.sll_ifindex=i.index,sll.sll_family=AF_PACKET,sll.sll_protocol=ETH_P_ARP;
	startmsg();

	importcidr(&block[0]);
	importcidr(&block[1]);
	
	rtts=calloc(try,sizeof(long long));
	if (!rtts)
		errx(1,"failed allocated time");

	/* recv buffer */
	if (!(buffer=calloc(1,65535)))
		errx(1,"failed allocated buffer for recv()");

	tot=mttl,first=ttl;
try:
	for (it=cvector_begin(targets);it!=cvector_end(targets);++it) {

		if (it->af==AF_INET&&!i.support4)
			errx(1,"this interface not suppport ipv4");
		if (it->af==AF_INET6&&!i.support6)
			errx(1,"this interface not suppport ipv6");
		
		nreceived=0,ntransmitted=0;
		tsum=0,tmin=LLONG_MAX,tmax=LLONG_MIN;
		ttl=first,mttl=tot-(ttl-1);	/* fix time */
		curtarget=*it,printstats=0;
		reached=0,lastipid=0,hop=0;
		memset(&source,0,sizeof(source));
		memset(&tmpip,0,sizeof(tmpip));

		for (;mttl;mttl--) {
			memset(rtts,0,(try*sizeof(long long)));
			p=success=0;
			printf("%d  ", ttl),fflush(stdout);
			for (hopid=1,ok=0;hopid<=try;hopid++) {
				nsdelay(interval);	/* delay ? */
				if (!(frame=tracerouteframe(&len,it,method,
						(u_char*)data,(u_int)datalen)))	/* create frame */
					errx(1,"failed create frame");
				if (sendto(fd,frame,len,0,(struct sockaddr*)&sll,sizeof(sll))<0)
					err(1,"failed send()");
				++ntransmitted;	/* success send */
				if (frame)
					free(frame);

				memset(&tstamp_s,0,sizeof(tstamp_s));
				memset(&tstamp_e,0,sizeof(tstamp_e));

				reply_state=0;
				frmrecv(fd,&buffer,65535,(void*)it,
					traceroutecallback,&tstamp_s,&tstamp_e,wait);
				nreceived+=(size_t)reply_state;

				/* process all */
				if (!reply_state&&all) {
					switch (method) {
						/* reroutes */
						case IPPROTO_ICMP:
							method=IPPROTO_TCP;
							break;
						case IPPROTO_TCP:
							method=IPPROTO_UDP;
							break;
						case IPPROTO_UDP:
							method=IPPROTO_SCTP;
							break;
						case IPPROTO_SCTP:
							method=IPPROTO_UDPLITE;
							break;
						case IPPROTO_UDPLITE:
							method=IPPROTO_ICMP;
							goto print;
					}
					hopid--;
					continue;
				}
print:
				if (reply_state) {
					rtts[hopid-1]=tvrtt(&tstamp_s,&tstamp_e);
					if (!p||a_cmp(&source,&tmpip)) {
						printf("%s %s",a_ntop_c(&source),resolve_dns(&source));
						p=1;
						tmpip=source;
					}
					if (!success)
						success=reply_state;
				}
				else {
					putchar('.');
					fflush(stdout);
				}
			}
			if (success) {
				printf("    ");
				for (j=1;j<=try;j++)
					printf("%s ",timefmt(rtts[j-1],time,sizeof(time)));
			}
			putchar(0x0a);
			if (reached)
				break;
			ttl++;
		}
		if (!printstats)
			stats(it),++printstats;
	}

	/* cidr ?? */
	cvector_clear(targets);
	if ((importcidr(&block[0]))!=0)
		goto try;
	if ((importcidr(&block[1]))!=0)
		goto try;

	finish(0);
	/* NOTREACHED */
}
