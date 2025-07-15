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
#include "include/addr.h"

typedef struct __cidr_block_t
{
	cvector(addr_t)	raw;	/* cidrs */
	size_t		cur;	/* current */
	size_t		curpos;	/* current position on cidr */
} cidr_block_t;

cvector(addr_t)		targets=NULL;	/* cvector_vector_type */
cidr_block_t		block;		/* cidr targets*/
struct timeval		_st,_et;	/* total time */
u_char			Iflag=0;
intf_t			i={0};
u_char			tflag=0;
addr_t			topt;
int			op=1;	/* default arp operation ARPREQUEST */
u_char			_0flag=0;
u_char			Bflag=0;
u_char			bflag=0;
size_t			num=10;	/* -n */
long long		delay=1000*1000000LL;
int			fd=-1;
u_char			fflag=0;
long long		wait=1000*1000000LL;
struct timeval		tstamp_s,tstamp_e;
u_char			*buffer=NULL;
u_char			Dflag=0;
u_char			reply_state=0;	/* last recv status */
size_t			nreceived=0,ntransmitted=0;
long long		tsum=0,tmin=LLONG_MAX,tmax=LLONG_MIN;
addr_t			curtarget;	/* current target */
u_char			printstats=0;	/* last stats print? */
u_char			lastmac[6];	/* last get mac */
u_char			eflag=0;
u_char			vflag=0;
u_char			lflag=0;
u_char			Lflag=0;
u_char			sflag=0;
addr_t			sopt;
size_t			Num=0;	/* -N */
u_char			Sflag=0;
addr_t			Sopt;
u_char			Gflag=0;
size_t			nbroadcast=0;	/* count broadcast frames */
size_t			nloss=0;	/* count loss frames */

static inline void
stats(addr_t *target)
{
	char t1[1000],t2[1000],t3[1000];	/* timestamps */

	if (!Dflag) {
		printf("\n----%s ARPING Statistics----\n",a_ntop_c(target));
		printf("%ld packets transmitted (%ld broadcast), %ld packets received",
			ntransmitted,nbroadcast,nreceived);
		if (ntransmitted) {
			if (nreceived>ntransmitted)
				printf(" -- somebody's printing up packets!\n");
			else
				printf(", %ld%% packet loss\n", (size_t)
					(((ntransmitted-nreceived)*100)/ntransmitted));
		}
		if (nreceived)
			printf("round-trip (rtt) min/avg/max = %s/%s/%s\n",
				timefmt(tmin,t1,sizeof(t1)),
				timefmt((long long)tsum/(long long)nreceived,
				t2,sizeof(t2)),timefmt(tmax,t3,sizeof(t3)));
		putchar(0x0a);
	}
	else {
		if (nreceived>ntransmitted)
			printf(" 0%% packet loss\n");
		if (ntransmitted)
			printf(" %ld%% packet loss\n",(size_t)
				(((ntransmitted-nreceived)*100)/ntransmitted));
	}
}

static inline noreturn void
finish(int sig)
{
	(void)sig;

	/* print stats if not print */
	if (!printstats)
		if (!(Lflag&&!reply_state))
			stats(&curtarget);

	gettimeofday(&_et,NULL);
	if (!Dflag)	/* end message */
		endmsg(&_st,&_et);
	if (fd>=0)	/* socket */
		close(fd);
	if (targets)	/* targets */
		cvector_free(targets);
	if (block.raw)	/* cidr targets */
		cvector_free(block.raw);
	if (buffer)	/* recv buffer */
		free(buffer);

	/* exit code */
	exit((nreceived)?0:1);
}

static inline int
importcidr(void)
{
	addr_t host;
	size_t n;

	/* cidr end */
	if ((block.cur)>=cvector_size(block.raw))
		return 0; /* close */

	for (n=0;n<30;n++) {	/* group 30 targets */
		if ((a_cnth(&block.raw[block.cur],
				(n+block.curpos),
				&host))==-1) {	/* is last */
			++block.cur;
			block.curpos=0;
			return 1;
		}
		cvector_push_back(targets,host);	/* add to targets */
	}

	/* save current pos in current
	 * cidr in block */
	block.curpos+=n;

	return 1;
}

static inline void
getopts(int c, char **av)
{
	const char	*ip;
	addr_t		addr;
	size_t		t;
	int		opt,n;

	if (c<=1) {
usage:
		puts("Usage");
		printf("  %s [options] <targets>\n\n",av[0]);
		puts("  -I <device>  set your interface and his info");
		puts("  -n <count>   set how many packets to send");
		puts("  -N <count>   set how many packets to recv (replies)");
		puts("  -o <num>     set your num operation, advice 1-4");
		puts("  -i <time>    set interval between packets, ex: see down");
		puts("  -S <source>  set source custom MAC address");
		puts("  -w <time>    set wait time or timeout, ex: 10s or 10ms");
		puts("  -t <mac>     set obviously target mac");
		puts("  -s <source>  set source custom IP address");
		putchar(0x0a);
		puts("  -b  keep on broadcasting, do not unicast");
		puts("  -f  quit on first reply");
		puts("  -0  use IP address 0.0.0.0 in spa");
		puts("  -B  use IP address 255.255.255.255 how target");
		puts("  -l  not display message for loss frames");
		puts("  -L  not display stats for down target");
		puts("  -G  use specified interface's _gateway as target");
		puts("  -D  display line mode (! reply) (. noreply)");
		puts("  -e  display info in easy (wireshark) style");
		puts("  -v  display all info, very verbose");
		puts("  -h  show this help message and exit");
		puts("\nExamples");
		printf("  %s 192.168.1.1 -f -e localhost\n",av[0]);
		printf("  %s -G -i 300ms\n",av[0]);
		printf("  %s -G -v -n 1000 -i 10ms -0\n",av[0]);
		exit(0);
	}

	while ((opt=getopt(c,av,"hI:t:o:Be0n:i:fw:Dbvs:N:S:GlL"))!=-1) {
		switch (opt) {
			case 'I':
				++Iflag;
				intfget(&i,optarg);
				/* check in main() */
				break;
			case 't':
				if ((a_pton(&topt,optarg))==-1)
					errx(1,"failed convert \"%s\" mac address",
						optarg);
				if (topt.af!=AFMAC)
					errx(1,"is not MAC address \"%s\"",
						optarg);
				tflag++;
				break;
			case 'o':
				str_to_size_t(optarg,&t,1,4);
				op=(int)t;
				break;
			case 'l':
				++lflag;
				break;
			case 'n':
				str_to_size_t(optarg,&t,1,SIZE_MAX);
				num=t;
				break;
			case 'L':
				++Lflag;
				break;
			case 'G':
				++Gflag;
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
			case 'S':
				if ((a_pton(&Sopt,optarg))==-1)
					errx(1,"failed convert \"%s\" mac address",
						optarg);
				if (Sopt.af!=AFMAC)
					errx(1,"is not MAC address \"%s\"",
						optarg);
				++Sflag;
				break;
			case 'D':
				++Dflag;
				break;
			case 'e':
				++eflag;
				break;
			case 'v':
				++vflag;
				break;
			case 'w':
				if ((wait=delayconv(optarg))==-1)
					errx(1,"failed convert %s time",
						optarg);
				break;
			case '0':
				++_0flag;
				break;
			case 'N':
				str_to_size_t(optarg,&t,1,SIZE_MAX);
				Num=t;
				break;
			case 'B':
				++Bflag;
				break;
			case 'b':
				++bflag;
				break;
			case 'i':
				if ((delay=delayconv(optarg))==-1)
					errx(1,"failed convert %s time",
						optarg);
				break;
			case 'f':
				++fflag;
				break;
			case '?': case 'h': default:
				goto usage;
		}
	}
	if (Bflag) {

		/* 255.255.255.255 */
		addr.af=AFIP4;
		addr.block.bits=-1;
		memset(addr.addr.ip4,0xff,4);
		cvector_push_back(targets,addr);

	} else if (Gflag) {
		/* ... see main()  */
	} else {
		n=c-optind;
		if (n<=0)
			goto usage;

		block.cur=0;
		block.curpos=0;

		for (n=optind;n<c;n++) {
			if ((a_pton(&addr,av[n]))==-1) {

				/* ok, this dns or fucking error? */
				if (!(ip=resolve_ipv4(av[n])))
					errx(1,"failed resolution \"%s\" name",av[n]);
				assert((a_pton(&addr,ip))!=-1);
			}
			switch (addr.af) {
				case AFIP6: case AFMAC:
					errx(1,"support only IPv4 address \"%s\"",av[n]);
				default:
					break;
					
			}
			if (addr.block.bits!=-1)
				cvector_push_back(block.raw,addr);
			else
				cvector_push_back(targets,addr);
		}
	}
}

static inline void
tvrtt(struct timeval *s, struct timeval *e)
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

	tsum+=rtt; /* update stats */
	tmax=(rtt>tmax)?rtt:tmax;
	tmin=(rtt<tmin)?rtt:tmin;
}

static inline u_char
arpcallback(u_char *arp, size_t arplen, void *arg)
{
	(void)arg;
	if (arplen<42)
		return 0;

	/* only arp frames */
	if (ntohs(*(u_short*)(void*)(arp+12))!=0x0806)
		return 0;
	if (tflag)	/* mac src */
		if (memcmp(arp+6,topt.addr.mac,6)!=0)
			return 0;

	/* opcode arp */
	switch (ntohs(*(u_short*)(void*)(arp+20))) {
		case 1: case 2: case 3: case 4:
			break;
		default:
			return 0;
	}
	switch (op) {
		case 1:
			/* wait ARP reply */
			if (ntohs(*(u_short*)(void*)(arp+20))!=2)
				return 0;
			/* check lastmac */
			if (!bflag&&lastmac[0]!='\n')
				if (memcmp(arp+22,lastmac,6)!=0)
					return 0;

			/* tpa and srcip4 must be identical; this kind
			 * of filtering is appropriate for types,
			 * 1,2,4. */
			if (memcmp((arp+38),i.srcip4,4)!=0)
				return 0;

			break;
		case 2:
			/* wait ARP request?? */
			if (ntohs(*(u_short*)(void*)(arp+20))!=1)
				return 0;
			if (memcmp((arp+38),i.srcip4,4)!=0)
				return 0;
			break;
		case 3:
			/* wait RARP reply */
			if (ntohs(*(u_short*)(void*)(arp+20))!=4)
				return 0;
			/* for RARP reply, check tha and srcmac */
			if (memcmp((arp+32),i.srcmac,6)!=0)
				return 0;
			break;
		case 4:
			/* wait RARP request?? */
			if (ntohs(*(u_short*)(void*)(arp+20))!=3)
				return 0;
			if (memcmp((arp+38),i.srcip4,4)!=0)
				return 0;
			break;
	}

	/* ARPHRD check and this darned FDDI hack here :-(
	 * iputils/arping.c */
	if (ntohs(*(u_short*)(void*)(arp+14))!=0x0001&&(/*0x0001!=
			0x0306||*/ntohs(*(u_short*)(void*)arp+14)
			!=htons(0x0001)))
		return 0;
	if ((ntohs(*(u_short*)(void*)(arp+14))==0x03)||
			(ntohs(*(u_short*)(void*)arp+14)==0x00)) {

		/* protocol type*/
		if (ntohs(*(u_short*)(void*)(arp+16))!=0xcc)
			return 0;
	} else if (ntohs(*(u_short*)(void*)(arp+16))!=0x0800)
		return 0;

	if (arp[18]!=6)	/* mac len */
		return 0;
	if (arp[19]!=4)	/* ip4 len */
		return 0;

	/* aee */
	memcpy(lastmac,arp+22,6);
	reply_state=1;
	return 1;
}

static inline void
arpinfo_easy(u_char *arp, size_t arplen, const char *rtt)
{
	assert(arp&&arplen);
	assert(arplen>=42);

	switch ((ntohs(*(u_short*)(void*)(arp+20)))) {
		case 1:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x ARP Who has"
				" %hhu.%hhu.%hhu.%hhu? Tell %hhu.%hhu.%hhu.%hhu",
				arplen,	/* packet length (size) */
				/* mac src */
				arp[6],arp[7],arp[8],arp[9],arp[10],arp[11],
				/* mac dst */
				arp[0],arp[1],arp[2],arp[3],arp[4],arp[5],
				arp[38],arp[39],arp[40],arp[41],	/* tpa */
				arp[28],arp[29],arp[30],arp[31]	/* spa */
			);
			break;
		case 2:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x ARP"
				" %hhu.%hhu.%hhu.%hhu at %02x:%02x:%02x:"
				"%02x:%02x:%02x",
				arplen,	/* packet length (size) */
				/* mac src */
				arp[6],arp[7],arp[8],arp[9],arp[10],arp[11],
				/* mac dst */
				arp[0],arp[1],arp[2],arp[3],arp[4],arp[5],
				arp[28],arp[29],arp[30],arp[31],	/* spa */
				/* sha */
				arp[22],arp[23],arp[24],arp[25],arp[26],arp[27]
			);
			break;
		case 3:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x RARP Who is"
				" %02x:%02x:%02x:%02x:%02x:%02x? Tell"
				" %02x:%02x:%02x:%02x:%02x:%02x",
				arplen,	/* packet length (size) */
				/* mac src */
				arp[6],arp[7],arp[8],arp[9],arp[10],arp[11],
				/* mac dst */
				arp[0],arp[1],arp[2],arp[3],arp[4],arp[5],
				/* tha */
				arp[32],arp[33],arp[34],arp[35],arp[36],arp[37],
				/* sha */
				arp[22],arp[23],arp[24],arp[25],arp[26],arp[27]
			);
			break;
		case 4:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x RARP"
				" %02x:%02x:%02x:%02x:%02x:%02x is at "
				"%hhu.%hhu.%hhu.%hhu",
				arplen,	/* packet length (size) */
				/* mac src */
				arp[6],arp[7],arp[8],arp[9],arp[10],arp[11],
				/* mac dst */
				arp[0],arp[1],arp[2],arp[3],arp[4],arp[5],
				/* tha */
				arp[32],arp[33],arp[34],arp[35],arp[36],arp[37],
				arp[38],arp[39],arp[40],arp[41] /* tpa */
			);
			break;
	}

	if (rtt)
		printf(" %s",rtt);

	putchar(0x0a);
}

static inline void
arpinfo_verbose(u_char *arp, size_t arplen, const char *rtt)
{
	assert(arp&&arplen);
	assert(arplen>=42);

	printf("%ld bytes",arplen);
	printf(" MAC {%02x:%02x:%02x:%02x:%02x:%02x > "
		"%02x:%02x:%02x:%02x:%02x:%02x 0x%02x%02x}",
		/* mac src */
		arp[6],arp[7],arp[8],arp[9],arp[10],arp[11],
		/* mac dst */
		arp[0],arp[1],arp[2],arp[3],arp[4],arp[5],
		/* payload type */
		arp[12],arp[13]
	);
	printf(" %s {%hu 0x%02x%02x %hhu %hhu %hu",
		/* proto */
		(((ntohs(*(u_short*)(void*)(arp+20))==1||
			ntohs(*(u_short*)(void*)(arp+20))==2)?
			"ARP":"RARP")),
		ntohs(*(u_short*)(void*)(arp+14)),	/* hrd type */
		arp[16],arp[17],			/* proto type */
		arp[18],arp[19],			/* hdr and proto addrlen */
		ntohs(*(u_short*)(void*)(arp+20))	/* operation */
	);
	printf("%02x:%02x:%02x:%02x:%02x:%02x|%hhu.%hhu.%hhu.%hhu",
		/* sha */
		arp[22],arp[23],arp[24],arp[25],arp[26],arp[27],
		/* spa */
		arp[28],arp[29],arp[30],arp[31]
	);
	printf(" > %02x:%02x:%02x:%02x:%02x:%02x|%hhu.%hhu.%hhu.%hhu}",
		/* tha */
		arp[32],arp[33],arp[34],arp[35],arp[36],arp[37],
		/* tpa */
		arp[38],arp[39],arp[40],arp[41]
	);
	printf(" ( %s )",(rtt)?rtt:"notime");
	putchar(0x0a);
}

static inline void
arpinfo(u_char *arp, size_t arplen, const char *rtt, size_t id)
{
	assert(arp&&arplen);
	assert(arplen>=42);

	printf("%ld bytes from %s %hhu.%hhu.%hhu.%hhu"
		" (%02x:%02x:%02x:%02x:%02x:%02x) id=%ld"
		" time=%s\n",
		arplen,	/* packet length (size) */

		/* arp operation code */
		((ntohs(*(u_short*)(void*)(arp+20))==1)?"arp-req":
		(ntohs(*(u_short*)(void*)(arp+20))==2)?"arp-reply":
		(ntohs(*(u_short*)(void*)(arp+20))==3)?"rarp-req":
		(ntohs(*(u_short*)(void*)(arp+20))==4)?"rarp-reply":
		"??? how?"),

		arp[28],arp[29],arp[30],arp[31], /* spa */
		/* sha */
		arp[22],arp[23],arp[24],arp[25],arp[26], arp[27],
		id,rtt	/* id pkt and rtt */
	);
}


static inline u_char *
arpframe(u_int *outlen, addr_t *target)
{
	u_char *arp;

	assert(target||outlen);
	*outlen=14+8+20;	/* eth + arp + arpreq */

	if (!(arp=calloc(1,*outlen)))
		errx(1,"failed allocated frame (%ld len)",*outlen);

	memset(arp,0xff,6);				/* dst mac */
	memcpy(arp+6,i.srcmac,6);			/* src mac */
	*(u_short*)(void*)(arp+12)=htons(0x0806);	/* arp payload */
	*(u_short*)(void*)(arp+14)=htons(0x0001);	/* ethernet */
	*(u_short*)(void*)(arp+16)=htons(0x0800);	/* ipv4 */
	arp[18]=6;					/* mac addr len */
	arp[19]=4;					/* ipv4 addr len */
	*(u_short*)(void*)(arp+20)=htons((u_short)op);	/* opcode */
	memcpy(arp+22,i.srcmac,6);			/* sha */
	memcpy(arp+28,i.srcip4,4);			/* spa */
	memset(arp+32,0xff,6);				/* tha */
	memcpy(arp+38,target->addr.ip4,4);		/* tpa */

	if (tflag) {
		memcpy(arp,topt.addr.mac,6);
		memcpy(arp+32,topt.addr.mac,6);
	} else if (reply_state&&!bflag&&
			lastmac[0]!='\n') {
		memcpy(arp,lastmac,6);
		memcpy(arp+32,lastmac,6);
	}

	return arp;
}

int
main(int c, char **av)
{
	/* vector iterator */
	cvector_iterator(addr_t) it;

	char			diff[1000];	/* for rtt */
	struct sockaddr_ll	sll;		/* sock addr */
	u_char			*arp=NULL;	/* arp frame */
	u_int			arplen=0;	/* size arp frame*/
	size_t			sum=0;		/* total frames */
	ssize_t			ret=0;		/* for recv frame */

	signal(SIGINT,finish);
	memset(&sll,0,sizeof(sll));	/* !! */
	gettimeofday(&_st,NULL);
	getopts(c,av);

	if (!Iflag)
		intfget_any(&i);
	else if (!intf_is_network_sendable(&i))
		errx(1,"this interface doesn't fit");
	if (!i.support4)
		errx(1,"this interface not suppport ipv4");
	if (_0flag)	/* src 0.0.0.0 */
		memset(i.srcip4,0x00,4);
	if (sflag)	/* src your*/
		memcpy(i.srcip4,sopt.addr.ip4,4);
	if (Sflag)	/* srcmac your */
		memcpy(i.srcmac,Sopt.addr.mac,6);
	if (Gflag) { /* gateway ut target */ 
		addr_t addr;
		addr.af=AFIP4;
		addr.block.bits=-1;
		memcpy(addr.addr.ip4,i.gatewayip4,4);
		cvector_push_back(targets,addr);
	}

	isroot();
	if ((fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
		errx(1,"failed create socket");

	/* fill address */
	sll.sll_ifindex=i.index,
		sll.sll_family=AF_PACKET,
		sll.sll_protocol=ETH_P_ARP;

	/* allocated buffer for master recv frames */
	if (!(buffer=calloc(1,65535)))
		errx(1,"failed allocated buffer for recv()");

	if (!Dflag)
		startmsg();
	importcidr();	/* add cidr targets */

	/* fix num frames */
	num=(fflag||Num)?1:num;
	sum=num;

try:
	for (it=cvector_begin(targets);it!=cvector_end(targets);++it) {

		/* update stats */
		nreceived=0,ntransmitted=0,nbroadcast=0,nloss=0;
		tsum=0,tmin=LLONG_MAX,tmax=LLONG_MIN;
		num=sum,curtarget=*it,printstats=0;
		arp=NULL,reply_state=0;
		lastmac[0]='\n';

		for (;num;num--) {

			/* update current reply status */
			reply_state=0;

			if (!(arp=arpframe(&arplen,it)))	/* create frame */
				errx(1,"failed create frame");
			if (sendto(fd,arp,arplen,0,(struct sockaddr*)&sll,
					sizeof(sll))<0)
				err(1,"failed send()");
			if (arp[0]==0xff&&arp[1]==0xff&&arp[2]==0xff
					&&arp[3]==0xff)
				++nbroadcast;	/* is broadcast frame */
			++ntransmitted;	/* success send */

			/* now, received packet */
			memset(&tstamp_s,0,sizeof(tstamp_s));
			memset(&tstamp_e,0,sizeof(tstamp_e));

			ret=frmrecv(fd,&buffer,65535,NULL,
				arpcallback,&tstamp_s,&tstamp_e,wait);
			if (ret<=0)
				reply_state=0;
			nreceived+=(size_t)reply_state;

			/* XXX error print
			 * sudo ./arping 192.168.1.33/24 -w 10ms -i 10ms -n 2 -lL -e
42 bytes 40:b0:76:47:8f:9a > ff:ff:ff:ff:ff:ff ARP Who has 192.168.1.35? Tell 192.168.1.33
60 bytes c0:e4:34:af:da:c3 > 40:b0:76:47:8f:9a ARP 192.168.1.35 at c0:e4:34:af:da:c3 5.02 ms

----192.168.1.35 ARPING Statistics----
2 packets transmitted (2 broadcast), 1 packets received, XXX -> 50% packet loss
round-trip (rtt) min/avg/max = 5.02 ms/5.02 ms/5.02 ms

XXX -> 42 bytes 40:b0:76:47:8f:9a > ff:ff:ff:ff:ff:ff ARP Who has 192.168.1.39? Tell 192.168.1.33

60 bytes c0:e4:34:af:da:c3 > 40:b0:76:47:8f:9a ARP 192.168.1.35 at c0:e4:34:af:da:c3 5.83 ms
42 bytes 40:b0:76:47:8f:9a > ff:ff:ff:ff:ff:ff ARP Who has 192.168.1.41? Tell 192.168.1.33
60 bytes f6:70:00:0f:48:43 > 40:b0:76:47:8f:9a ARP 192.168.1.41 at f6:70:00:0f:48:43 372.00 μs
42 bytes 40:b0:76:47:8f:9a > ff:ff:ff:ff:ff:ff ARP Who has 192.168.1.41? Tell 192.168.1.33
60 bytes f6:70:00:0f:48:43 > 40:b0:76:47:8f:9a ARP 192.168.1.41 at f6:70:00:0f:48:43 335.00 μs

----192.168.1.41 ARPING Statistics----
2 packets transmitted (2 broadcast), 2 packets received, 0% packet loss
round-trip (rtt) min/avg/max = 335.00 μs/353.50 μs/372.00 μs

			 */

			/* print sent frame (-e, -v) */
			if (!Dflag) {
				if (!(lflag&&!reply_state)) {
					if (eflag)
						arpinfo_easy(arp,arplen,NULL);
					if (vflag)
						arpinfo_verbose(arp,arplen,NULL);
				}
			}
			/* free sent frame */
			if (arp)
				free(arp);

			if (reply_state) {
				tvrtt(&tstamp_s,&tstamp_e);	/* updates stats rtt */
				if (!Dflag) {
					if (eflag)
						arpinfo_easy(buffer,(size_t)ret,timediff(&tstamp_s,
							&tstamp_e, diff,sizeof(diff)));
					else if (vflag)
						arpinfo_verbose(buffer,(size_t)ret,timediff(&tstamp_s,
							&tstamp_e, diff,sizeof(diff)));
					else 
						arpinfo(buffer,(size_t)ret,timediff(&tstamp_s,&tstamp_e,
							diff,sizeof(diff)),sum-num);
				}
			}
			else {
				++nloss;	/* loss frame */
				lastmac[0]='\n';	/* change??? HOW? */
				if (fflag)
					++num;	/* until there's an answer  */
				if (!Dflag&&!lflag)
					printf("- loss transmission within the specified timeout"
						" (%ld%% total) id=%ld\n",
						(((ntransmitted-nreceived)*100)/ntransmitted),
						nloss);
			}

			if (Dflag) {
				if (!(lflag&&!reply_state))
					putchar((reply_state)?'!':'.');
				fflush(stdout);
			}
			if (Num&&nreceived<Num&&!fflag)
				++num;
			if ((num-1)) /* interval */
				nsdelay(delay);
		}
		if (!printstats)
			if (!(Lflag&&!reply_state))
				stats(it),++printstats;
	}

	/* cidr not empty ? */
	cvector_clear(targets);
	if (importcidr()!=0)
		goto try;

	finish(0);
	/* NOTREACHED */
}
