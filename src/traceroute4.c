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
#include "../include/random.h"
#include "../include/utils.h"

cvector(u_int)		targets=NULL;	/* cvector_vector_type */
struct timeval		_st,_et;	/* total time */
u_char			Iflag=0;
intf_t			i={0};
int			mttl=30,ttl=1;	/* max ttl and ttl */
u_int			soptip=0;
u_char			sflag=0;
u_char			Sflag=0;
u_char			Soptmac[6];
char			*data=NULL;	/* payload */
size_t			datalen=0;
u_char			oflag=0;
u_char			oopt=0;
int			off=0;
int			fd=-1;
u_char			Pflag=0;
u_short			Popt=0;
u_char			pflag=0;
u_short			popt=0;

static inline noreturn void finish(int sig)
{
	gettimeofday(&_et,NULL);
	endmsg(&_st,&_et);

	if (fd>=0)	/* socket */
		close(fd);
	if (data)
		free(data);
	if (targets)
		cvector_free(targets);	/* targets */
	exit(sig);
}

static inline u_char *tracerouteframe(u_int *outlen, u_int target,
	 int proto, u_char *_data, u_int _datalen)
{
	u_char *frame;
	int n;

	assert(proto);
	assert(outlen);

	*outlen=0;
	switch (proto) {
		case IPPROTO_TCP:
			*outlen+=20;
			break;
		case IPPROTO_SCTP:
			*outlen+=16;	/* sctp + cookie chunk */
			break;
		case IPPROTO_ICMP:	/* icmp + echo msg*/
		case IPPROTO_UDPLITE:
		case IPPROTO_UDP:
			*outlen+=8;
			break;
	}
	*outlen+=14;	/* ethernet 2 */
	*outlen+=20;	/* ipv4 */
	*outlen+=_datalen;

	if (!(frame=calloc(1,*outlen)))
		errx(1,"failed allocated frame (%ld len)",*outlen);

	memcpy(frame,i.dstmac,6);				/* dst mac */
	memcpy(frame+6,i.srcmac,6);				/* src mac */
	*(u_short*)(void*)(frame+12)=htons(0x0800);		/*ippayload*/

	frame[14]=(4<<4)|5/*5+(optslen/4)*/;			/* version|ihl */
	frame[15]=(oflag)?oopt:0;				/* tos */
	*(u_short*)(void*)(frame+16)=htons((u_short)		/* tot_len +optslen */
		(*outlen-14));
	*(u_short*)(void*)(frame+18)=htons(random_u16());	/* id */
	*(u_short*)(void*)(frame+20)=htons((u_short)off);	/* off */
	frame[22]=(u_char)randnum(121,255);			/* ttl */
	frame[23]=(u_char)proto;				/* proto */
	*(u_short*)(void*)(frame+24)=0;				/* chksum */
	for(n=0;n<4;n++)					/* src+dst */
		frame[26+n]=i.srcip4[n], /* via in caelum*/
		frame[30+n]=(ntohl(target)>>(24-8*n))&0xff;
	*(u_short*)(void*)(frame+24)=in_check((u_short*)(void*)(frame+14),20);


	switch (proto) {
		case IPPROTO_ICMP:
			frame[34]=8;						/* type */
			frame[35]=0;						/* code */
			*(u_short*)(void*)(frame+36)=htons(0);			/* chksum */
			*(u_short*)(void*)(frame+38)=htons(random_u16());	/* id */
			*(u_short*)(void*)(frame+40)=htons(1);			/* seq */
			if (_data&&_datalen)
			    memcpy(frame+42,_data,_datalen);
			*(u_short*)(void*)(frame+36)=in_check((u_short*)
				(void*)(frame+34),(int)(8+_datalen));
			break;
		case IPPROTO_TCP:
			*(u_short*)(void*)(frame+34)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+36)=(pflag)?htons(popt):htons(80);		/* dst port */
			memcpy(frame+38,&(u_int){htonl(random_u32())},sizeof(u_int));		/* seq */
			memcpy(frame+42,&(u_int){htonl(0)},sizeof(u_int));			/* ack */
			frame[46]=(5<<4)|(0&0x0f);						/* off | res */
			frame[47]=2;								/* flags */
			*(u_short*)(void*)(frame+48)=htons(1024);				/* window */
			*(u_short*)(void*)(frame+50)=0;						/* chksum */
			*(u_short*)(void*)(frame+52)=0;						/* urp */
			if(_data&&_datalen)
				memcpy(frame+54,_data,_datalen);
			*(u_short*)(void*)(frame+50)=ip4_pseudocheck(
				htonl((u_int)(((u_int)i.srcip4[0]<<24)|((u_int)i.srcip4[1]<<16)|
				((u_int)i.srcip4[2]<<8)|(u_int)i.srcip4[3])),target,IPPROTO_TCP,
				(20+(u_short)_datalen),(frame+34));
			break;
		case IPPROTO_SCTP:
			*(u_short*)(void*)(frame+34)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+36)=(pflag)?htons(popt):htons(80);		/* dst port */
			*(u_int*)(void*)(frame+38)=htonl(random_u32());				/* vtag */
			*(u_int*)(void*)(frame+42)=htonl(0);					/* chksum */
			frame[46]=0x0a;								/* type */
			frame[47]=0;								/* flags */
			*(u_short*)(void*)(frame+48)=htons(4+(u_short)_datalen);		/* len */
			if(_data&&_datalen)
				memcpy(frame+50,_data,_datalen);
			*(u_int*)(void*)(frame+42)=htonl(adler32(1,(frame+34),16+_datalen));	/* final chksum */
			break;
		case IPPROTO_UDP:
			*(u_short*)(void*)(frame+34)=(Pflag)?htons(Popt):htons(random_u16());	/* src port */
			*(u_short*)(void*)(frame+36)=(pflag)?htons(popt):htons(80);		/* dst port */
			*(u_short*)(void*)(frame+38)=htons(8+(u_short)_datalen);		/* len */
			*(u_short*)(void*)(frame+40)=htons(0);					/* chksum */
			if(_data&&_datalen)
				memcpy(frame+42,_data,_datalen);
			*(u_short*)(void*)(frame+40)=ip4_pseudocheck(
				htonl((u_int)(((u_int)i.srcip4[0]<<24)|((u_int)i.srcip4[1]<<16)|
				((u_int)i.srcip4[2]<<8)|(u_int)i.srcip4[3])),target,IPPROTO_UDP,
				(8+(u_short)_datalen),(frame+34));
			break;
		case IPPROTO_UDPLITE:
			*(u_short*)(void*)(frame+34)=(Pflag)?htons(Popt):htons(random_u16());   /* src port */
			*(u_short*)(void*)(frame+36)=(pflag)?htons(popt):htons(80);             /* dst port */
			*(u_short*)(void*)(frame+38)=htons(0);                                  /* checkcrg */
			*(u_short*)(void*)(frame+40)=htons(0);                                  /* chksum */
			if (_data&&_datalen)
				memcpy(frame+42,_data,_datalen);
			*(u_short*)(void*)(frame+40)=ip4_pseudocheck(
				htonl((u_int)(((u_int)i.srcip4[0]<<24)|((u_int)i.srcip4[1]<<16)|
				((u_int)i.srcip4[2]<<8)|(u_int)i.srcip4[3])),target,IPPROTO_UDPLITE,
				(8+(u_short)_datalen),(frame+34));
			break;
	}

	return frame;
}

static inline void getopts(int argc, char **argv)
{
	struct ether_addr	*tmp;
	const char		*ip;
	u_int			a,b,c,d;
	int			opt,n;
	size_t			numtmp;
	u_char			*hextmp;

	if (argc<=1) {
usage:
		puts("Usage");
		printf("  %s [flags] <target target1 ...,>\n\n",argv[0]);
		puts("  -I <device>  set your interface and his info");
		puts("  -s <source>  set source custom IP address");
		puts("  -S <source>  set source custom MAC address");
		puts("  -o <tos>     set your Type Of Service");
		puts("  -P <port>    set source (your) port");
		puts("  -m <ttl>     set max ttl (num hops)");
		puts("  -f <ttl>     set first ttl (start hop)");
		puts("  -p <port>    set destination port");
		puts("  -H <hex>     set payload in hex numbers");
		puts("  -a <ascii>   set payload in ascii");
		puts("  -l <length>  set payload in ascii");

		putchar(0x0a);
		puts("  -r  set Reserved Fragment flag");
		puts("  -d  set Dont't Fragment flag");
		puts("  -4  set More Fragment flag");
		puts("  -h  show this help message and exit");
		puts("\nExamples");
		exit(0);
	}

	while ((opt=getopt(argc,argv,"hI:s:S:o:P:p:H:a:l:dr4m:f:"))!=-1) {
		switch (opt) {
			case 'I':
				++Iflag;
				intfget(&i,optarg);
				/* check in main() */
				break;
			case 'f':
				str_to_size_t(optarg,&numtmp,0,USHRT_MAX);
				ttl=(int)numtmp;
				break;
			case 'm':
				str_to_size_t(optarg,&numtmp,0,USHRT_MAX);
				mttl=(int)numtmp;
				break;
			case 'd':
				off|=0x4000;
				break;
			case 'r':
				off|=0x8000;
				break;
			case '4':
				off|=0x2000;
				break;
			case 's':
				if ((soptip=inet_addr(optarg))==INADDR_NONE)
					errx(1,"failed convert \"%s\" this (ipv4?)",
						optarg);
				++sflag;
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
				if (!(tmp=ether_aton(optarg)))
					errx(1,"failed convert \"%s\" mac address",
						optarg);
				memcpy(Soptmac,tmp->ether_addr_octet,6);
				++Sflag;
				break;
			case '?': case 'h': default:
				goto usage;
		}
	}
	n=argc-optind;
	if (n<=0)
		goto usage;
	for (n=optind;n<argc;n++) {
		if (sscanf(argv[n],"%u.%u.%u.%u",&a,&b,&c,&d)!=4) {
			/* ok, this dns or fucking error? */
			if (!(ip=resolve_ipv4(argv[n])))
				errx(1,"failed resolution \"%s\" name",argv[n]);
			assert((sscanf(ip,"%u.%u.%u.%u",&a,&b,&c,&d)==4));
		}
		assert(a>=0&&a<=255&&b>=0&&b<=255&&c>=0&&c<=255&&d>=0&&d<=255);
		cvector_push_back(targets,(htonl((a<<24)|(b<<16)|(c<<8)|d)));
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_ll	sll={0};
	u_char			*frame=NULL;
	u_int			len=0;
	cvector_iterator(u_int)	it;

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
		memcpy(i.srcip4,&soptip,4);
	if (Sflag)	/* srcmac your */
		memcpy(i.srcmac,Soptmac,4);
	if (datalen>(size_t)i.mtu-100)
		errx(1, "your mtu-100 is (%ld), your length"
			" data is \"%d\"",i.mtu-100,datalen);
	isroot();
	if ((fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
		errx(1,"failed create socket");
	sll.sll_ifindex=i.index,sll.sll_family=AF_PACKET,sll.sll_protocol=ETH_P_ARP;
	startmsg();

	for (it=cvector_begin(targets);it!=cvector_end(targets);++it) {
		if (!(frame=tracerouteframe(&len,*it,IPPROTO_UDPLITE,
			(u_char*)data,(u_int)datalen)))	/* create frame */
			errx(1,"failed create frame");
		printf("%u\n",len);
		if (sendto(fd,frame,len,0,(struct sockaddr*)&sll,sizeof(sll))<0)
			err(1,"failed send()");
		free(frame);
	}

	finish(0);
	/* NOTREACHED */
}

