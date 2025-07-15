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

#include "../include/utils.h"

const char *
timediff(struct timeval *s, struct timeval *e,
		char *out, size_t outlen)
{
	long long st,mc,ns;

	st=e->tv_sec-s->tv_sec;
	mc=e->tv_usec-s->tv_usec;

	if (mc<0) {
		st-=1;
		mc+=1000000;
	}

	ns=st*1000000000LL+mc*1000LL;
	return timefmt(ns,out,outlen);
}

const char *
timefmt(long long ns, char *out, size_t outlen)
{
	const char *prefixes[]={"ns","μs","ms",
			"sec","min","h"};
	double	val;
	int	prfx;

	val=(double)ns;
	prfx=0;

	if (val>=3600000000000.0) {
		prfx=5;
		val/=3600000000000.0;
	} else if (val>=60000000000.0) {
		prfx=4;
		val/=60000000000.0;
	} else if (val>=1000000000.0) {
		prfx=3;
		val/=1000000000.0;
	} else if (val>=1000000.0) {
		prfx=2;
		val/=1000000.0;
	} else if (val>=1000.0) {
		prfx=1;
		val/=1000.0;
	} else
		prfx=0;

	snprintf(out,outlen,"%.2f %s",val,prefixes[prfx]);
	return out;
}

const char *
strdate(char *out, size_t outlen)
{
	struct tm	*t;
	time_t		now;

	now=time(NULL);
	t=localtime(&now);

	strftime(out,outlen,"%Y-%m-%d %H:%M:%S",t);
	return out;
}

char *
resolve_ipv4(const char *hostname)
{
	static char		ip[INET_ADDRSTRLEN];
	struct addrinfo		hints,*res;
	struct sockaddr_in	*addr,sa_in;

	bzero(ip,sizeof(ip));
	bzero(&hints,sizeof(hints));
	hints.ai_family=AF_INET;

	if (getaddrinfo(hostname,NULL,&hints,&res)==0) {
		memcpy(&sa_in,res->ai_addr,sizeof(sa_in));
		addr=&sa_in;
		inet_ntop(AF_INET,&addr->sin_addr,ip,sizeof(ip));
		freeaddrinfo(res);
		return ip;
	}

	return NULL;
}

void
nsdelay(long long ns)
{
	struct timespec	req,rem;

	req.tv_sec=(ns/1000000000);
	req.tv_nsec=(ns%1000000000);

	nanosleep(&req,&rem);
}

long long
delayconv(const char *txt)
{
	char		unit[3]={0};
	long long	res;
	char		*endptr;
	size_t		len;

	if(txt==NULL||*txt=='\0')
		return -1;
	if(strcmp(txt,"0")==0)
		return 1;

	res=strtoll(txt,&endptr,10);
	if(*endptr=='\0')
		return res;

	len=strlen(endptr);
	if(len>2)
		return -1;

	strncpy(unit,endptr,2);
	if(res==0)
		return 1;

	if(strcmp(unit,"ms")==0)
		return res*1000000LL;
	else if(strcmp(unit,"s")==0)
		return res*1000000000LL;
	else if(strcmp(unit,"m")==0)
		return res*60000000000LL;
	else if(strcmp(unit,"h")==0)
		return res*3600000000000LL;

	return -1;
}

static inline struct timeval
timevalns(long long ns)
{
	struct timeval tv;

	tv.tv_sec=ns/1000000000LL;
	tv.tv_usec=(ns%1000000000LL)/1000;

	return tv;
}

ssize_t
frmrecv(int fd, u_char **buf, size_t buflen,void *arg, rcall_t callback,
                struct timeval *tstamp_s,struct timeval *tstamp_e,
		long long ns)
{
	struct timespec	s,c;
	struct timeval	timeout;
	struct pollfd	pfd;
	u_char		*tmpbuf;
	ssize_t		ret;

	assert(buf);
	assert(callback);
	assert(fd>=0);
	assert(buflen>0);

	ret=0;
	tmpbuf=NULL;
	bzero(&s,sizeof(s));
	bzero(&c,sizeof(c));
	bzero(&timeout,sizeof(timeout));
	bzero(&pfd,sizeof(pfd));
	
	pfd.fd=fd;
	pfd.events=POLLIN;

	timeout=timevalns(ns);
	setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));

	tmpbuf=*buf;
	clock_gettime(CLOCK_MONOTONIC,&s);
	gettimeofday(tstamp_s,NULL);

	for (;;) {
		ret=poll(&pfd,1,(int)(ns/1000000));
		if (ret==-1) {
			if (errno==EINTR)
				continue;
			return -1;
		}
		else if (ret==0)
			return -1;
		else if (pfd.revents&POLLIN) {
			pfd.revents=0;
			ret=recv(fd,tmpbuf,buflen,0);
			gettimeofday(tstamp_e,NULL);
			if (ret==-1) {
				if (errno==EINTR)
					continue;
				return -1;
			}
			if (!callback(tmpbuf,(size_t)ret,arg)) {
				clock_gettime(CLOCK_MONOTONIC,&c);
				if (((c.tv_sec-s.tv_sec)*1000000000LL+
						(c.tv_nsec-s.tv_nsec))>=ns)
					return -1;
				continue;
			}
			else {
				*buf=tmpbuf;
				return ret;
			}
		}
	}
}

void
str_to_size_t(const char *str, size_t *out, size_t min, size_t max)
{
	unsigned long long	val;
	char			*endptr;

	assert(str||*str||out);
	while (isspace((u_char)*str))
		str++;
	if (*str=='-')
		errx(1,"only positive numbers");
	errno=0;
 	val=strtoull(str,&endptr,10);
	if (errno==ERANGE||val>(unsigned long long)SIZE_MAX)
		err(1,"failed convert %s in num",str);
	while (isspace((u_char)*endptr))
		endptr++;
	if (*endptr!='\0')
		errx(1,"failed convert %s in num",str);
	if (val<min||val>max)
		errx(1,"failed convert %s in num; range failure (%ld-%llu)",
			str,min,max);
	*out=(size_t)val;
}

#define ip_check_carry(x) \
	(x=(x>>16)+(x&0xffff),(~(x+(x>>16))&0xffff))

static inline int
ip_check_add(const void *buf, size_t len, int check)
{
	u_short	*sp=(u_short*)buf;
	size_t	n,sn;

	sn=len/2;
	n=(sn+15)/16;
	switch (sn%16) {
		case 0: do {
			check+=*sp++;
		case 15:
			check+=*sp++;
		case 14:
			check+=*sp++;
		case 13:
			check+=*sp++;
		case 12:
			check+=*sp++;
		case 11:
			check+=*sp++;
		case 10:
			check+=*sp++;
		case 9:
			check+=*sp++;
		case 8:
			check+=*sp++;
		case 7:
			check+=*sp++;
		case 6:
			check+=*sp++;
		case 5:
			check+=*sp++;
		case 4:
			check+=*sp++;
		case 3:
			check+=*sp++;
		case 2:
			check+=*sp++;
		case 1:
			check+=*sp++;
		} while (--n>0);
	}

	if (len&1)
		check+=htons((uint16_t)(*(u_char*)sp<<8));
	return check;
}

u_short
in_check(u_short *ptr, int nbytes)
{
	int sum;
	sum=ip_check_add(ptr,(size_t)nbytes,0);
	return ip_check_carry(sum);
}

u_short
ip4_pseudocheck(const u_char *src, const u_char *dst,
		u_char proto, u_short len, const void *hstart)
{
	struct pseudo {
		u_char	src[4];
		u_char	dst[4];
		u_char	zero;
		u_char	proto;
		u_short	length;
	} hdr;
	int sum;

	assert(src);
	assert(dst);
	assert(hstart);
	assert(len);

	memcpy(hdr.src,src,4);
	memcpy(hdr.dst,dst,4);
	hdr.zero=0;
	hdr.proto=proto;
	hdr.length=htons(len);

	sum=ip_check_add(&hdr, sizeof(hdr), 0);
	sum=ip_check_add(hstart, len, sum);
	sum=ip_check_carry(sum);

	/* RFC 768: "If the computed  checksum  is zero,  it is transmitted  as all
	* ones (the equivalent  in one's complement  arithmetic).   An all zero
	* transmitted checksum  value means that the transmitter  generated  no
	* checksum" */
	if (proto==IPPROTO_UDP&&sum==0)
		sum=0xFFFF;

	return (u_short)sum;
}

u_short
ip6_pseudocheck(u_char *src, u_char *dst, u_char nxt,
		 u_int len, const void *hstart)
{
	struct pseudo {
		u_char	src[16];
		u_char	dst[16];
		u_int	length;
		u_char	z0, z1, z2;
		u_char	nxt;
	} hdr;
	int sum;

	assert(src);
	assert(dst);
	assert(hstart);
	assert(len);

	memcpy(hdr.src,src,16);
	memcpy(hdr.dst,dst,16);
	hdr.z0=hdr.z1=hdr.z2=0;
	hdr.length=htonl(len);
	hdr.nxt=nxt;

	sum=ip_check_add(&hdr, sizeof(hdr), 0);
	sum=ip_check_add(hstart, len, sum);
	sum=ip_check_carry(sum);

	if (nxt==IPPROTO_UDP&&sum==0)
		sum=0xFFFF;	

	return (u_short)sum;
}

#define BASE 65521U
#define NMAX 5552

#define DO1(buf,i)  {adler += (buf)[i]; sum2 += adler;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

#if defined (HAVE_DIVIDE_SUPPORT)
  #define MOD(a) a %= BASE
  #define MOD28(a) a %= BASE
  #define MOD63(a) a %= BASE
#else
#define CHOP(a)					\
  do {						\
    unsigned long tmp = a >> 16;		\
    a &= 0xffffUL;				\
    a += (tmp << 4) - tmp;			\
  } while (0)
#define MOD28(a)				\
  do {						\
    CHOP(a);					\
    if (a >= BASE) a -= BASE;			\
  } while (0)
#define MOD(a)					\
  do {						\
    CHOP(a);					\
    MOD28(a);					\
  } while (0)
#define MOD63(a)				\
  do {						\
    i64 tmp = a >> 32;				\
    a &= 0xffffffffL;				\
    a += (tmp << 8) - (tmp << 5) + tmp;		\
    tmp = a >> 16;				\
    a &= 0xffffL;				\
    a += (tmp << 4) - tmp;			\
    tmp = a >> 16;				\
    a &= 0xffffL;				\
    a += (tmp << 4) - tmp;			\
    if (a >= BASE) a -= BASE;			\
  } while (0)
#endif

u_int
adler32(u_int adler, const u_char *buf, size_t len)
{
	unsigned long	sum2;
	u_int		n;

	sum2=(adler>>16)&0xffff;
	adler&=0xffff;

	if (len==1){
		adler+=buf[0];
		if (adler>=BASE)
			adler-=BASE;
		sum2+=adler;
		if (sum2>=BASE)
			sum2-=BASE;
		return adler|((u_int)sum2<<16);
	}

	if (buf==0)
		return 1L;

	if (len<16) {
		while (len--) {
			adler+=*buf++;
			sum2+=adler;
		}
		if (adler>=BASE)
			adler-=BASE;
		MOD28(sum2);
		return adler|((u_int)sum2<<16);
	}

	while (len>=NMAX) {
		len-=NMAX;
		n=NMAX/16;
		do {
			DO16(buf);
			buf+=16;
		} while (--n);
		MOD(adler);
		MOD(sum2);
	}

	if (len) {
		while (len>=16) {
			len-=16;
			DO16(buf);
			buf+=16;
		}
		while (len--) {
			adler+=*buf++;
			sum2+=adler;
		}
		MOD(adler);
		MOD(sum2);
	}

	return adler|((u_int)sum2<<16);
}

/* thanks nmap */
u_char *
hex_ahtoh(char *txt, size_t *hexlen)
{
	static u_char	dst[16384];
	size_t		dstlen=16384;
	char		auxbuff[1024];
	char		*start=NULL;
	char		twobytes[3];
	u_int		i=0,j=0;

	if (!txt||!hexlen)
		return NULL;
	if (strlen(txt)==0)
		return NULL;
	memset(auxbuff,0,1024);
	if (!strncmp("0x", txt, 2)) {
		if (strlen(txt)==2)
			return NULL;
		start=txt+2;
	}
	else if(!strncmp("\\x", txt, 2)) {
		if (strlen(txt)==2)
			return NULL;
		for (i=0;i<strlen(txt)&&j<1023;i++)
			if(txt[i]!='\\'&&txt[i]!='x'&&txt[i]!='X')
				auxbuff[j++]=txt[i];
		auxbuff[j]='\0';
		start=auxbuff;
	}
	else
		start=txt;
	for (i=0;i<strlen(start);i++)
		if (!isxdigit(start[i]))
			return NULL;
	if (strlen(start)%2!=0)
		return NULL;
	for (i=0,j=0;j<dstlen&&i<strlen(start)-1;i+=2) {
		twobytes[0]=start[i];
		twobytes[1]=start[i+1];
		twobytes[2]='\0';
		dst[j++]=(u_char)strtol(twobytes, NULL, 16);
	}

	*hexlen=j;
	return dst;
}
