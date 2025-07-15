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

#include "../include/addr.h"

static inline int
__p_ipv4(u_char *out_ip, const char *txt)
{
	char	*ep;
	long	n;
	int	j;

	if (!out_ip||!txt)
		return -1;
	ep=(char*)txt;
	while (*ep) {
		if (!isdigit((u_char)*ep)&&*ep!='.')
			return -1;
		++ep;
	}
	ep=NULL;
	for (j=0;j<4;j++) {
		n=strtol(txt,&ep,10);
		if (n<0x0||n>0xff||ep==txt||(j<3&&*ep!='.'))
			break;
		out_ip[j]=(u_char)n;
		txt=ep+1;
	}

	return ((j==4&&*ep=='\0')?0:-1);
}

static inline int
__p_ipv6(u_char *out_ip6, const char *txt)
{
	u_short	data[8];
	u_short	*u;
	int	i,j,n,z;
	char	*ep;
	long	l;

	if (!out_ip6||!txt)
		return -1;
	ep=(char*)txt;
	while (*ep) {
		if (!isxdigit((u_char)*ep)&&*ep!=':'&&
				*ep!='.'&&!isdigit((u_char)*ep))
			return -1;
		++ep;
	}
	ep=NULL;

	u=(u_short*)(void*)out_ip6;
	i=j=n=z=-1;

	if (*txt==':')
		txt++;
	for (n=0;n<8;n++) {
		l=strtol(txt,&ep,16);
		if (ep==txt) {
			if (ep[0]==':'&&z==-1)
				z=n,txt++;
			else if (ep[0]=='\0')
				break;
			else
				return -1;
		}
		else if (ep[0]=='.'&&n<=6) {
			if (__p_ipv4((u_char*)(data+n),txt)==-1)
				return -1;
			n+=2,ep="";
			break;
		}
		else if (l>=0&&l<=0xffff) {
			data[n]=htons((u_short)l);
			if (ep[0]=='\0') {
				n++;
				break;
			}
			else if (ep[0]!=':'||ep[1]=='\0')
				return -1;
			txt=ep+1;
		}
		else
			return -1;
	}

	if (n==0||*ep!='\0'||(z==-1&&n!=8))
		return -1;
	for (i=0;i<z;i++)
		u[i]=data[i];
	while (i<8-(n-z-1))
		u[i++]=0;
	for (j=z+1;i<8;i++,j++)
		u[i]=data[j];

	return 0;
}

static inline int
__p_mac(u_char *out_mac, const char *txt)
{
	char	*ep;
	char	s;
	long	n;
	int	j;

	if (!out_mac||!txt)
		return -1;
	ep=(char*)txt;
	while (*ep) {
		if (!isxdigit((u_char)*ep)&&*ep!=':'&&*ep!='-')
			return -1;
		++ep;
	}
	ep=NULL;
	for (j=0;j<6;j++) {
		n=strtol(txt,&ep,16);
		if (n<0x0||n>0xff||ep==txt)
			break;
		out_mac[j]=(u_char)n;
		if (j==0) {
			if (*ep==':'||*ep=='-')
				s=*ep;
			else if (j<5)
				break;
		}
		if (j<5) {
			if (*ep!=s)
				break;
			txt=ep+1;
		}
		else
			txt=ep;
	}

	return ((j==6&&*ep=='\0')?0:-1);
}

static inline int
__broadcast(addr_t *a)
{
	int i,j;
	if (!a||a->block.bits==-1)
		return -1;
	for (i=0;i<=15;i++) {
		for (j=7;j>=0;j--) {
			if ((a->block.mask[i]&(1<<j))) {
				switch (a->af) {
					case AFIP4:
						a->block.broadcast[i]|=
							(a->addr.ip4[i]&1<<j);
						break;
					case AFIP6:
						a->block.broadcast[i]|=
							(a->addr.ip6[i]&1<<j);
						break;
					default:
						return -1;
				}
			}
			else
				a->block.broadcast[i]|=(1<<j);
		}
	}
	return 0;
}

static inline int
__network(addr_t *a)
{
	int i,j;
	if (!a||a->block.bits==-1)
		return -1;
	for (i=0;i<=15;i++) {
		for (j=7;j>=0;j--) {
			if ((a->block.mask[i]&(1<<j))) {
				switch (a->af) {
					case AFIP4:
						a->block.network[i]|=
							(a->addr.ip4[i]&(1<<j));
						break;
					case AFIP6:
						a->block.network[i]|=
							(a->addr.ip6[i]&(1<<j));
						break;
					default:
						return -1;
				}
			}
		}
	}
	return 0;
}

static inline int
__btom(addr_t *a)
{
	u_char *ptr;
	u_int mtmp;
	int n,h;

	if (!a||a->block.bits==-1)
		return -1;
	switch (a->af) {
		case AFIP4:
			mtmp=(a->block.bits)?htonl
				(0xffffffff<<(32-a->block.bits)):0;
			memcpy(a->block.mask,&mtmp,4);
			break;
		case AFIP6:
			ptr=(u_char*)a->block.mask;
			n=a->block.bits/8,h=a->block.bits%8;
			if (n>0)
				memset(ptr,0xff,(u_long)n);
			if (n<16) {
				ptr[n]=(u_char)(h)?(u_char)(0xff<<(8-h)):0x00;
				if (n+1<16)
					memset(ptr+n+1,0x00,(u_long)(16-n-1));
			}
			break;
		default:
			return -1;
	}
	return 0;
}

int
a_pton(addr_t *a, const char *cp)
{
	char		p1[256];
	const char	*sp,*ap;

	if (!a||!cp)
		return -1;

	memset(a->block.mask,0,16);
	memset(a->block.network,0,16);
	memset(a->block.broadcast,0,16);
	a->block.bits=-1;
	a->af=-1;
	ap=cp;

	/* cidr process */
	if ((sp=strchr(cp,'/'))) {
		char	p2[strlen(cp)-(sp-cp)],
			*ep=NULL;

		if ((u_long)(sp-cp)>=sizeof(p1))
			return -1;

		strncpy(p1,cp,(u_long)(sp-cp));
		p1[(sp-cp)]='\0';
		strcpy(p2,sp+1);
		ep=p2;
		while (*ep) {	/* only numbers */
			if (!isdigit((u_char)*ep))
				return -1;
			ep++;
		}
		errno=0,ep=NULL;
		a->block.bits=(int)strtol(p2,&ep,10);
		if (errno!=0||ep==p2||*ep!='\0'||a->block.bits<0)
			return -1;
		ap=p1;
	}

	/* addr process */
	if (__p_ipv4(a->addr.ip4,ap)!=-1) {
		if (a->block.bits>32)
			return -1;
		a->af=AFIP4;
		__btom(a);
		__broadcast(a);
		__network(a);
		return 0;
	}
	else if (__p_ipv6(a->addr.ip6,ap)!=-1) {
		if (a->block.bits>128)
			return -1;
		a->af=AFIP6;
		__btom(a);
		__broadcast(a);
		__network(a);
		return 0;
	}
	else if (__p_mac(a->addr.mac,ap)!=-1) {
		if (a->block.bits!=-1)	/* no bits */
			return -1;
		a->af=AFMAC;
		return 0;
	}
	return -1;
}

static const char *octet2hex[]={
	"00","01","02","03","04","05","06","07","08","09","0a",
	"0b","0c","0d","0e","0f","10","11","12","13","14","15",
	"16","17","18","19","1a","1b","1c","1d","1e","1f","20",
	"21","22","23","24","25","26","27","28","29","2a","2b",
	"2c","2d","2e","2f","30","31","32","33","34","35","36",
	"37","38","39","3a","3b","3c","3d","3e","3f","40","41",
	"42","43","44","45","46","47","48","49","4a","4b","4c",
	"4d","4e","4f","50","51","52","53","54","55","56","57",
	"58","59","5a","5b","5c","5d","5e","5f","60","61","62",
	"63","64","65","66","67","68","69","6a","6b","6c","6d",
	"6e","6f","70","71","72","73","74","75","76","77","78",
	"79","7a","7b","7c","7d","7e","7f","80","81","82","83",
	"84","85","86","87","88","89","8a","8b","8c","8d","8e",
	"8f","90","91","92","93","94","95","96","97","98","99",
	"9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4",
	"a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
	"b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba",
	"bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5",
	"c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0",
	"d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db",
	"dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6",
	"e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1",
	"f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc",
	"fd","fe","ff"
};

static inline int
__n_mac(u_char *mac, char *dst, size_t dstlen)
{
	const char	*x;
	char		*ptr;
	int		n;

	if (!mac||!dst||!dstlen)
		return -1;
	if (dstlen<18)
		return -1;
	ptr=dst;
	for (n=0;n<6;n++) {
		for (x=octet2hex[mac[n]];(*ptr=*x)!='\0';x++,ptr++);
		*ptr++=':';
	}
	ptr[-1]='\0';
	return 0;
}

static const char *octet2dec[]={
	"0","1","2","3","4","5","6","7","8","9","10","11","12",
	"13","14","15","16","17","18","19","20","21","22","23",
	"24","25","26","27","28","29","30","31","32","33","34",
	"35","36","37","38","39","40","41","42","43","44","45",
	"46","47","48","49","50","51","52","53","54","55","56",
	"57","58","59","60","61","62","63","64","65","66","67",
	"68","69","70","71","72","73","74","75","76","77","78",
	"79","80","81","82","83","84","85","86","87","88","89",
	"90","91","92","93","94","95","96","97","98","99","100",
	"101","102","103","104","105","106","107","108","109",
	"110","111","112","113","114","115","116","117","118",
	"119","120","121","122","123","124","125","126","127",
	"128","129","130","131","132","133","134","135","136",
	"137","138","139","140","141","142","143","144","145",
	"146","147","148","149","150","151","152","153","154",
	"155","156","157","158","159","160","161","162","163",
	"164","165","166","167","168","169","170","171","172",
	"173","174","175","176","177","178","179","180","181",
	"182","183","184","185","186","187","188","189","190",
	"191","192","193","194","195","196","197","198","199",
	"200","201","202","203","204","205","206","207","208",
	"209","210","211","212","213","214","215","216","217",
	"218","219","220","221","222","223","224","225","226",
	"227","228","229","230","231","232","233","234","235",
	"236","237","238","239","240","241","242","243","244",
	"245","246","247","248","249","250","251","252","253",
	"254","255"
};

static inline int
__n_ipv4(u_char *ipv4, char *dst, size_t dstlen)
{
	const char	*d;
	char		*ptr;
	int		n;

	if (!ipv4||!dst||!dstlen)
		return -1;
	if (dstlen<16)
		return -1;
	ptr=dst;
	for (n=0;n<4;n++) {
		for(d=octet2dec[ipv4[n]];(*ptr=*d)!='\0';d++,ptr++);
		*ptr++='.';
	}
	ptr[-1]='\0';
	return 0;
}

/* libdnet */
static inline int
__n_ipv6(u_char *ipv6, char *dst, size_t dstlen)
{
	struct {int base,len;}	best,cur;
	u_short			*ip6_data;
	char			*p;
	int			i;

	if (!ipv6||!dst||!dstlen)
		return -1;
	if (dstlen<46)
		return -1;
	p=dst;
	cur.len=best.len=0;
	best.base=cur.base=-1;

	/*
	 * Algorithm borrowed from Vixie's inet_pton6()
	 */
	for(i=0;i<16;i+=2){
		ip6_data=(u_short*)(void*)&ipv6[i];
		if (*ip6_data==0) {
			if (cur.base==-1) {
				cur.base=i;
				cur.len=0;
			}
			else
				cur.len+=2;
		}
		else {
			if (cur.base!=-1) {
				if (best.base==-1||cur.len>best.len)
					best=cur;
				cur.base=-1;
			}
		}
	}
	if (cur.base!=-1&&(best.base==-1||cur.len>best.len))
		best=cur;
	if (best.base!=-1&&best.len<2)
		best.base=-1;
	if (best.base==0)
		*p++=':';
	for (i=0;i<16;i+=2) {
		if (i==best.base) {
			*p++=':';
			i+=best.len;
		}
		else if (i==12&&best.base==0&&(best.len==10||
				(best.len==8&&*(ip6_data=
				(u_short*)(void*)&ipv6[10])==0xffff))) {
			if (__n_ipv4(&ipv6[12],p,(size_t)(dstlen-(size_t)(p-dst)))==-1)
				return -1;
			return 0;
		}
		else
			p+=sprintf(p,"%x:",ntohs(*(ip6_data=
				(u_short*)(void*)&ipv6[i])));
	}
	if (best.base+2+best.len==16)
		*p='\0';
	else
		p[-1]='\0';

	return 0;
}

int
a_ntop(addr_t *a, char *dst, size_t dstlen)
{
	char buffer[2048],bits[64];

	if (!a||!dst||!dstlen)
		return -1;
	if (a->block.bits!=-1)
		snprintf(bits,sizeof(bits),
			"/%d",a->block.bits);
	else
		bits[0]='\0';

	switch (a->af) {
		case AFIP4:
			if ((__n_ipv4(a->addr.ip4,buffer,
					sizeof(buffer)))==-1)
				return -1;
			break;
		case AFMAC:
			if ((__n_mac(a->addr.mac,buffer,
					sizeof(buffer)))==-1)
				return -1;
			break;
		case AFIP6:
			if ((__n_ipv6(a->addr.ip6,buffer,
					sizeof(buffer)))==-1)
				return -1;
			break;
	}

	if (dstlen<(size_t)(snprintf(dst,dstlen,"%s%s",buffer,
			bits)+1))
		return -1;

	return 0;
}

char *
a_ntop_c(addr_t *a)
{
	static char temp[65535];
	if (!a)
		return NULL;
	if ((a_ntop(a,temp,sizeof(temp)))==-1)
		return NULL;
	return temp;
}

#ifdef HAVE_UINT128
int
a_cnth(addr_t *a, __uint128_t n, addr_t *dst)
{
	__uint128_t n6=0,max;
	u_int n4;
	int i;

	if (!a||!dst||a->block.bits==-1)
		return -1;
	dst->block.bits=-1;
	dst->af=a->af;
	
	switch (a->af) {
		case AFIP4:
			max=(a->block.bits>=32)?1:((__uint128_t)1<<(32-a->block.bits));
			if (n>=max)
				return -1;
			memcpy(&n4,a->block.network,4);
			n4=ntohl(n4);
			n4+=(u_int)n;
			n4=htonl(n4);
			memcpy(dst->addr.ip4,&n4,4);
			break;
		case AFIP6:
			if (a->block.bits>=128)
				max=1;
			else if (a->block.bits==0)
				max=~(__uint128_t)0;
			else
				max=(__uint128_t)1<<(128-a->block.bits);
			if (n>=max)
				return -1;
			for (i=0;i<16;i++) {
				n6<<=8;
				n6|=a->block.network[i];
			}
			n6+=n;
			for (i=15;i>=0;i--) {
				dst->addr.ip6[i]=(u_char)(n6&0xFF);
				n6>>=8;
			}
			break;
		default:
			return -1;
	}
	return 0;
}
#else
int
a_cnth(addr_t *a, size_t n, addr_t *dst)
{
	u_char	n6[16];
	u_short	val;
	u_int	n4;
	int	i;
	size_t	max;

	if (!a||!dst||a->block.bits==-1)
		return -1;
	dst->block.bits=-1;
	dst->af=a->af;

	switch (a->af) {
		case AFIP4:
			max=(a->block.bits>=32)?
				1:(size_t)1<<(32-a->block.bits);
			if (n>=max)
				return -1;
			memcpy(&n4,a->block.network,4);
			n4=ntohl(n4);
			n4+=n;
			n4=htonl(n4);
			memcpy(dst->addr.ip4,&n4,4);
			break;
		case AFIP6:
			if (a->block.bits>=128)
				max=1;
			else if (a->block.bits<=64)
				max=(size_t)1<<(128-a->block.bits);
			else {
				max=(size_t)1<<(128-a->block.bits-64);
				/* size_t small... */
				if (max>0)
					max=0;
				else
					return -1;
			}
			if (max>0&&n>=max)
				return -1;
			memcpy(&n6,a->block.network,16);
			for (i=15;i>=0&&n>0;i--) {
				val=n6[i]+(n&0xff);
				n6[i]=val&0xff;
				n=(n>>8)+(val>>8);
			}
			memcpy(dst->addr.ip6,n6,16);
			break;
		default:
			return -1;
	}
	return 0;
}
#endif

int
a_cmp(const addr_t *a, const addr_t *b)
{
	u_long n;
	if (!a||!b)
		return -1;
	if ((a->af!=b->af))
		return -1;
	if ((a->block.bits!=b->block.bits))
		return -1;
	switch (a->af) {
		case AFIP4:
			if (memcmp(a->addr.ip4,b->addr.ip4,4)!=0)
				return -1;
			if (a->block.bits==-1)
				return 0;
			n=4;
			break;
		case AFIP6:
			if (memcmp(a->addr.ip6,b->addr.ip6,16)!=0)
				return -1;
			if (a->block.bits==-1)
				return 0;
			n=16;
			break;
		case AFMAC:
			if (memcmp(a->addr.mac,b->addr.mac,6)!=0)
				return -1;
			return 0;
		default:
			return -1;
	}
	if (memcmp(a->block.mask,b->block.mask,n)!=0)
		return -1;
	if (memcmp(a->block.network,b->block.network,n)!=0)
		return -1;
	if (memcmp(a->block.broadcast,b->block.broadcast,n)!=0)
		return -1;
	return 0;
}

int
a_bcast(const addr_t *a, addr_t *b)
{
	if (!a||!b||a->block.bits==-1)
		return -1;
	b->af=a->af;
	b->block.bits=-1;
	switch (a->af) {
		case AFIP4:
			memcpy(b->addr.ip4,a->block.broadcast,4);
			break;
		case AFIP6:
			memcpy(b->addr.ip6,a->block.broadcast,16);
			break;
		default:
			return -1;
	}
	return 0;
}

int
a_net(const addr_t *a, addr_t *b)
{
	if (!a||!b||a->block.bits==-1)
		return -1;
	b->af=a->af;
	b->block.bits=-1;
	switch (a->af) {
		case AFIP4:
			memcpy(b->addr.ip4,a->block.network,4);
			break;
		case AFIP6:
			memcpy(b->addr.ip6,a->block.network,16);
			break;
		default:
			return -1;
	}
	return 0;
}

int
a_mask(const addr_t *a, addr_t *b)
{
	if (!a||!b||a->block.bits==-1)
		return -1;
	b->af=a->af;
	b->block.bits=-1;
	switch (a->af) {
		case AFIP4:
			memcpy(b->addr.ip4,a->block.mask,4);
			break;
		case AFIP6:
			memcpy(b->addr.ip6,a->block.mask,16);
			break;
		default:
			return -1;
	}
	return 0;
}

/*
int main(void)
{
	char buf[1024];
	addr_t addr;
	int n;


	memset(&addr,0,sizeof(addr));
	if ((a_pton(&addr,"192.168.1.1/27"))!=-1) {
		addr_t tmp;

		n=a_ntop(&addr,buf,sizeof(buf));
		printf("RES (%d)\t%s\n",n,buf);

		a_mask(&addr,&tmp);
		n=a_ntop(&tmp,buf,sizeof(buf));
		printf("MSK \t%s\n",buf);

		a_bcast(&addr,&tmp);
		n=a_ntop(&tmp,buf,sizeof(buf));
		printf("BRD \t%s\n",buf);

		a_net(&addr,&tmp);
		n=a_ntop(&tmp,buf,sizeof(buf));
		printf("NET \t%s\n",buf);
		putchar(0x0a);
		
		addr_t t;
		memset(&t,0,sizeof(t));
		n=a_cnth(&addr,31,&t);
		a_ntop(&t,buf,sizeof(buf));
		printf("RES (%d)\t%s\n",n,buf);
	}
	memset(&addr,0,sizeof(addr));
	if ((a_pton(&addr,"40:b0:76:47:8f:9a"))!=-1) {
		n=a_ntop(&addr,buf,sizeof(buf));
		printf("RES (%d)\t%s\n",n,buf);
		putchar(0x0a);
	}
	memset(&addr,0,sizeof(addr));
	if ((a_pton(&addr,"::/0"))!=-1) {
		addr_t tmp;

		n=a_ntop(&addr,buf,sizeof(buf));
		printf("RES (%d)\t%s\n",n,buf);

		a_mask(&addr,&tmp);
		n=a_ntop(&tmp,buf,sizeof(buf));
		printf("MSK \t%s\n",buf);

		a_bcast(&addr,&tmp);
		n=a_ntop(&tmp,buf,sizeof(buf));
		printf("BRD \t%s\n",buf);

		a_net(&addr,&tmp);
		n=a_ntop(&tmp,buf,sizeof(buf));
		printf("NET \t%s\n",buf);

		putchar(0x0a);

		addr_t t;
		memset(&t,0,sizeof(t));
		n=a_cnth(&addr,(~(__uint128_t)0)-1,&t);
		a_ntop(&t,buf,sizeof(buf));
		printf("RES (%d)\t%s\n",n,buf);
	}
	return 0;
}
*/
