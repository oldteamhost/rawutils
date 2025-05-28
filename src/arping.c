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

#include "../include/include.h"
#include "../include/intf.h"
#include "../include/cvector.h"
#include "../include/utils.h"

cvector(u_int)		targets=NULL;	/* cvector_vector_type */
struct timeval		_st,_et;	/* total time */
u_char			Iflag=0;
intf_t			i={0};
u_char			tflag=0;
u_char			topt[6]={0};
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
u_int			curtarget=0;	/* current target */
u_char			printstats=0;	/* last stats print? */
u_char			lastmac[6];	/* last get mac */
u_char			eflag=0;
u_char			vflag=0;
u_char			sflag=0;
u_int			soptip=0;
size_t			Num=0;	/* -N */
u_char			Sflag=0;
u_char			Soptmac[6];
u_char			Gflag=0;
size_t			nbroadcast=0;	/* count broadcast frames */
size_t			nloss=0;	/* count loss frames */

static inline void stats(u_int target)
{
	char t1[1000],t2[1000],t3[1000];
	struct in_addr in;

	if (!Dflag) {
		in.s_addr=target;
		printf("\n----%s ARPING Statistics----\n",inet_ntoa(in));
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
				timefmt((long long)tsum/(long long)nreceived,t2,sizeof(t2)),
				timefmt(tmax,t3,sizeof(t3)));
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

static inline noreturn void finish(int sig)
{
	(void)sig;
	/* print stats if not print */
	if (!printstats)
		stats(curtarget);
	gettimeofday(&_et,NULL);
	if (!Dflag)
		endmsg(&_st,&_et);
	if (fd>=0)	/* socket */
		close(fd);
	if (targets)
		cvector_free(targets);	/* targets */
	if (buffer)	/* recv buffer */
		free(buffer);

	if (nreceived)
		exit(0);
	else
		exit(1);
}

static inline void getopts(int argc, char **argv)
{
	struct ether_addr	*tmp;
	const char		*ip;
	u_int			a,b,c,d;
	int			opt,n;
	size_t			numtmp;

	if (argc<=1) {
usage:
		puts("Usage");
		printf("  %s [flags] <target target1 ...,>\n\n",argv[0]);
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
		puts("  -G  use specified interface's _gateway as target");
		puts("  -D  display line mode (! reply) (. noreply)");
		puts("  -e  display info in easy (wireshark) style");
		puts("  -v  display all info, very verbose");
		puts("  -h  show this help message and exit");
		puts("\nExamples");
		printf("  %s 192.168.1.1 -f -e localhost\n",argv[0]);
		printf("  %s -G -i 300ms\n",argv[0]);
		printf("  %s -G -v -n 1000 -i 10ms -0\n",argv[0]);
		exit(0);
	}

	while ((opt=getopt(argc,argv,"hI:t:o:Be0n:i:fw:Dbvs:N:S:G"))!=-1) {
		switch (opt) {
			case 'I':
				++Iflag;
				intfget(&i,optarg);
				/* check in main() */
				break;
			case 't':
				tflag++;
				if (!(tmp=ether_aton(optarg)))
					errx(1,"failed convert \"%s\" mac address",
						optarg);
				memcpy(topt,tmp->ether_addr_octet,6);
				break;
			case 'o':
				str_to_size_t(optarg,&numtmp,1,4);
				op=(int)numtmp;
				break;
			case 'n':
				str_to_size_t(optarg,&numtmp,1,SIZE_MAX);
				num=numtmp;
				break;
			case 'G':
				++Gflag;
				break;
			case 's':
				if ((soptip=inet_addr(optarg))==INADDR_NONE)
					errx(1,"failed convert \"%s\" this (ipv4?)",
						optarg);
				++sflag;
				break;
			case 'S':
				if (!(tmp=ether_aton(optarg)))
					errx(1,"failed convert \"%s\" mac address",
						optarg);
				memcpy(Soptmac,tmp->ether_addr_octet,6);
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
				str_to_size_t(optarg,&numtmp,1,SIZE_MAX);
				Num=numtmp;
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
		a=b=c=d=255;
		cvector_push_back(targets,(htonl((a<<24)|(b<<16)|(c<<8)|d)));
	}
	else if (Gflag) {
		/* ... see main()  */
	}
	else {
		n=argc-optind;
		if (n<=0)
			goto usage;
		for (n=optind;n<argc;n++) {
			if (sscanf(argv[n],"%d.%d.%d.%d",&a,&b,&c,&d)!=4) {
				/* ok, this dns or fucking error? */
				if (!(ip=resolve_ipv4(argv[n])))
					errx(1,"failed resolution \"%s\" name",argv[n]);
				assert((sscanf(ip,"%u.%u.%u.%u",&a,&b,&c,&d)==4));
			}
			assert(a>=0&&a<=255&&b>=0&&b<=255&&c>=0&&c<=255&&d>=0&&d<=255);
			cvector_push_back(targets,(htonl((a<<24)|(b<<16)|(c<<8)|d)));
		}
	}
}

static inline void tvrtt(struct timeval *s, struct timeval *e)
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
}

static inline u_char arpcallback(u_char *frame, size_t frmlen, void *arg)
{
	(void)arg;
	if (frmlen<42)
		return 0;

	/* only arp frames */
	if (ntohs(*(u_short*)(void*)(frame+12))!=0x0806)
		return 0;
	if (tflag)	/* mac src */
		if (memcmp(frame+6,topt,6)!=0)
			return 0;
	/* opcode arp */
	switch (ntohs(*(u_short*)(void*)(frame+20))) {
		case 1: case 2: case 3: case 4:
			break;
		default:
			return 0;
	}
	switch (op) {
		case 1:
			/* wait ARP reply */
			if (ntohs(*(u_short*)(void*)(frame+20))!=2)
				return 0;
			/* check lastmac */
			if (!bflag&&lastmac[0]!='\n')
				if (memcmp(frame+22,lastmac,6)!=0)
					return 0;
			/* tpa and srcip4 must be identical; this kind
			 * of filtering is appropriate for types,
			 * 1,2,4.
			 */
			if (memcmp((frame+38),i.srcip4,4)!=0)
				return 0;
			break;
		case 2:
			/* wait ARP request?? */
			if (ntohs(*(u_short*)(void*)(frame+20))!=1)
				return 0;
			if (memcmp((frame+38),i.srcip4,4)!=0)
				return 0;
			break;
		case 3:
			/* wait RARP reply */
			if (ntohs(*(u_short*)(void*)(frame+20))!=4)
				return 0;
			/* for RARP reply, check tha and srcmac */
			if (memcmp((frame+32),i.srcmac,6)!=0)
				return 0;
			break;
		case 4:
			/* wait RARP request?? */
			if (ntohs(*(u_short*)(void*)(frame+20))!=3)
				return 0;
			if (memcmp((frame+38),i.srcip4,4)!=0)
				return 0;
			break;
	}

	/* ARPHRD check and this darned FDDI hack here :-(
	 * iputils/arping.c */
	if (ntohs(*(u_short*)(void*)(frame+14))!=0x0001&&(/*0x0001!=
			0x0306||*/ntohs(*(u_short*)(void*)frame+14)
			!=htons(0x0001)))
		return 0;
	if ((ntohs(*(u_short*)(void*)(frame+14))==0x03)||
			(ntohs(*(u_short*)(void*)frame+14)==0x00)) {
		/* protocol type*/
		if (ntohs(*(u_short*)(void*)(frame+16))!=0xcc)
			return 0;
	}
	else if (ntohs(*(u_short*)(void*)(frame+16))!=0x0800)
		return 0;

	if (frame[18]!=6)	/* mac len */
		return 0;
	if (frame[19]!=4)	/* ip4 len */
		return 0;

	/* aee */
	memcpy(lastmac,frame+22,6);
	reply_state=1;
	return 1;
}

static inline void arpinfo_easy(u_char *frame, size_t frmlen, const char *rtt)
{
	assert(frame&&frmlen);
	assert(frmlen>=42);

	switch ((ntohs(*(u_short*)(void*)(frame+20)))) {
		case 1:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x ARP Who has"
				" %hhu.%hhu.%hhu.%hhu? Tell %hhu.%hhu.%hhu.%hhu",
				frmlen,	/* packet length (size) */
				/* mac src */
				frame[6],frame[7],frame[8],frame[9],frame[10],frame[11],
				/* mac dst */
				frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],
				frame[38],frame[39],frame[40],frame[41],	/* tpa */
				frame[28],frame[29],frame[30],frame[31]	/* spa */);
			break;
		case 2:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x ARP"
				" %hhu.%hhu.%hhu.%hhu at %02x:%02x:%02x:%02x:%02x:%02x",
				frmlen,	/* packet length (size) */
				/* mac src */
				frame[6],frame[7],frame[8],frame[9],frame[10],frame[11],
				/* mac dst */
				frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],
				frame[28],frame[29],frame[30],frame[31],	/* spa */
				/* sha */
				frame[22],frame[23],frame[24],frame[25],frame[26],frame[27]);
			break;
		case 3:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x RARP Who is"
				" %02x:%02x:%02x:%02x:%02x:%02x? Tell"
				" %02x:%02x:%02x:%02x:%02x:%02x",
				frmlen,	/* packet length (size) */
				/* mac src */
				frame[6],frame[7],frame[8],frame[9],frame[10],frame[11],
				/* mac dst */
				frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],
				/* tha */
				frame[32],frame[33],frame[34],frame[35],frame[36],frame[37],
				/* sha */
				frame[22],frame[23],frame[24],frame[25],frame[26],frame[27]);
			break;
		case 4:
			printf("%ld bytes %02x:%02x:%02x:%02x:%02x:%02x"
				" > %02x:%02x:%02x:%02x:%02x:%02x RARP"
				" %02x:%02x:%02x:%02x:%02x:%02x is at %hhu.%hhu.%hhu.%hhu",
				frmlen,	/* packet length (size) */
				/* mac src */
				frame[6],frame[7],frame[8],frame[9],frame[10],frame[11],
				/* mac dst */
				frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],
				/* tha */
				frame[32],frame[33],frame[34],frame[35],frame[36],frame[37],
				frame[38],frame[39],frame[40],frame[41] /* tpa */);
			break;
	}
	if (rtt)
		printf(" %s\n",rtt);
	else
		putchar(0x0a);
}

static inline void arpinfo_verbose(u_char *frame, size_t frmlen, const char *time)
{
	assert(frame&&frmlen);
	assert(frmlen>=42);

	printf("%ld bytes",frmlen);
	printf(" MAC {%02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x 0x%02x%02x}",
		/* mac src */
		frame[6],frame[7],frame[8],frame[9],frame[10],frame[11],
		/* mac dst */
		frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],
		/* payload type */
		frame[12],frame[13]);
	printf(" %s {%hu 0x%02x%02x %hhu %hhu %hu",
		/* proto */
		(((ntohs(*(u_short*)(void*)(frame+20))==1||
			ntohs(*(u_short*)(void*)(frame+20))==2)?
			"ARP":"RARP")),
		ntohs(*(u_short*)(void*)(frame+14)),	/* hrd type */
		frame[16],frame[17],			/* proto type */
		frame[18],frame[19],			/* hdr and proto addr len */
		ntohs(*(u_short*)(void*)(frame+20))		/* operation */
		);
	printf("%02x:%02x:%02x:%02x:%02x:%02x|%hhu.%hhu.%hhu.%hhu",
		/* sha */
		frame[22],frame[23],frame[24],frame[25],frame[26],frame[27],
		/* spa */
		frame[28],frame[29],frame[30],frame[31]);
	printf(" > %02x:%02x:%02x:%02x:%02x:%02x|%hhu.%hhu.%hhu.%hhu}",
		/* tha */
		frame[32],frame[33],frame[34],frame[35],frame[36],frame[37],
		/* tpa */
		frame[38],frame[39],frame[40],frame[41]);
	printf(" ( %s )",(time)?time:"notime");
	putchar(0x0a);
}

static inline void arpinfo(u_char *frame, size_t frmlen, const char *time, size_t id)
{
	assert(frame&&frmlen);
	assert(frmlen>=42);

	printf("%ld bytes from %s %hhu.%hhu.%hhu.%hhu"
		" (%02x:%02x:%02x:%02x:%02x:%02x) id=%ld"
		" time=%s\n",
		frmlen,	/* packet length (size) */
		/* arp operation code */
		((ntohs(*(u_short*)(void*)(frame+20))==1)?"arp-req":
		(ntohs(*(u_short*)(void*)(frame+20))==2)?"arp-reply":
		(ntohs(*(u_short*)(void*)(frame+20))==3)?"rarp-req":
		(ntohs(*(u_short*)(void*)(frame+20))==4)?"rarp-reply":
		"??? how?"),
		frame[28],frame[29],frame[30],frame[31],	/* spa */
		/* sha */
		frame[22],frame[23],frame[24],frame[25],
		frame[26],frame[27],
		id,time); /* id pkt and rtt */
}

static inline u_char *arpframe(u_int *outlen, u_int target)
{
	u_char *frame;

	assert(outlen),*outlen=14+8+20;	/* eth + arp + arpreq */
	if (!(frame=calloc(1,*outlen)))
		errx(1,"failed allocated frame (%ld len)",*outlen);

	memset(frame,0xff,6);				/* dst mac */
	memcpy(frame+6,i.srcmac,6);			/* src mac */
	*(u_short*)(void*)(frame+12)=htons(0x0806);	/* arp payload */
	*(u_short*)(void*)(frame+14)=htons(0x0001);	/* ethernet */
	*(u_short*)(void*)(frame+16)=htons(0x0800);	/* ipv4 */
	frame[18]=6;					/* mac addr len */
	frame[19]=4;					/* ipv4 addr len */
	*(u_short*)(void*)(frame+20)=			/* opcode */
			htons((u_short)op);
	memcpy(frame+22,i.srcmac,6);			/* sha */
	memcpy(frame+28,i.srcip4,4);			/* spa */
	memset(frame+32,0xff,6);			/* tha */
	memcpy(frame+38,&target,4);			/* tpa */

	if (tflag) {
		memcpy(frame,topt,6);
		memcpy(frame+32,topt,6);
	}
	else if (reply_state&&!bflag&&lastmac[0]!='\n') {
		memcpy(frame,lastmac,6);
		memcpy(frame+32,lastmac,6);
	}

	if (!Dflag) {	/* print packet for -e -v */
		if (eflag)
			arpinfo_easy(frame,*outlen,NULL);
		if (vflag)
			arpinfo_verbose(frame,*outlen,NULL);
	}

	return frame;
}

int main(int argc, char **argv)
{
	struct sockaddr_ll	sll={0};
	cvector_iterator(u_int)	it;
	u_char			*frame=NULL;
	char			diff[1000];
	size_t			tot=0;
	ssize_t			ret=0;
	u_int			len=0;

	signal(SIGINT,finish);
	gettimeofday(&_st,NULL);
	getopts(argc,argv);

	if (!Iflag)
		intfget_any(&i);
	else if (!intf_is_network_sendable(&i))
		errx(1,"this interface doesn't fit");
	if (_0flag)	/* src 0.0.0.0 */
		memset(i.srcip4,0x00,4);
	if (sflag)	/* src your*/
		memcpy(i.srcip4,&soptip,4);
	if (Sflag)	/* srcmac your */
		memcpy(i.srcmac,Soptmac,4);
	if (Gflag) /* gateway ut target */
		cvector_push_back(targets, htonl(((u_int)i.gatewayip4[0]<<24)|
			((u_int)i.gatewayip4[1]<<16)|((u_int)i.gatewayip4[2]<<8)|
			(u_int)i.gatewayip4[3]));

	isroot();
	if ((fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
		errx(1,"failed create socket");
	sll.sll_ifindex=i.index,sll.sll_family=AF_PACKET,sll.sll_protocol=ETH_P_ARP;

	/* recv buffer */
	if (!(buffer=calloc(1,65535)))
		errx(1,"failed allocated buffer for recv()");

	if (!Dflag)
		startmsg();
	num=(fflag||Num)?1:num,tot=num;
	for (it=cvector_begin(targets);it!=cvector_end(targets);++it) {

		/* update stats */
		nreceived=0,ntransmitted=0,nbroadcast=0,nloss=0;
		tsum=0,tmin=LLONG_MAX,tmax=LLONG_MIN;
		num=tot,curtarget=*it,printstats=0;
		lastmac[0]='\n';

		for (;num;num--) {
			if (!(frame=arpframe(&len,*it)))	/* create frame */
				errx(1,"failed create frame");
			if (sendto(fd,frame,len,0,(struct sockaddr*)&sll,sizeof(sll))<0)
				err(1,"failed send()");
			if (frame[0]==0xff&&frame[1]==0xff&&frame[2]==0xff
					&&frame[3]==0xff)
				++nbroadcast;	/* is broadcast frame */
			++ntransmitted;	/* success send */
			if (frame)
				free(frame);

			/* now, received packet */
			memset(&tstamp_s,0,sizeof(tstamp_s));
			memset(&tstamp_e,0,sizeof(tstamp_e));

			reply_state=0;
			ret=frmrecv(fd,&buffer,65535,NULL,
				arpcallback,&tstamp_s,&tstamp_e,wait);
			nreceived+=(size_t)reply_state;

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
							diff,sizeof(diff)),tot-num);
				}
			}
			else {
				++nloss;	/* loss frame */
				lastmac[0]='\n';	/* change??? HOW? */
				if (fflag)
					++num;	/* until there's an answer  */
				if (!Dflag)
					printf("- loss transmission within the specified timeout"
						" (%ld%% total) id=%ld\n",
						(((ntransmitted-nreceived)*100)/ntransmitted),
						nloss);
			}
			if (Dflag) {
				putchar((reply_state)?'!':'.');
				fflush(stdout);
			}
			if (Num&&nreceived<Num&&!fflag)
				++num;
			if ((num-1)) /* interval */
				nsdelay(delay);
		}
		if (!printstats)
			stats(*it),++printstats;
	}

	finish(0);
	/* NOTREACHED */
}
