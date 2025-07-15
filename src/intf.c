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

#include "../include/intf.h"

static inline int
__intf_ipv6_src_get(intf_t *i, const char *ifname)
{
	u_int	index,prefix_len,scope,flags;
	char	dev[256],addr[512],s[8][5];
	FILE	*f;

	if (!(f=fopen("/proc/net/if_inet6","r"))) {
		errx(1,"failed open /proc/net/if_inet6 for get srcip6"
			" for %s interface",ifname);
		return 0;
	}
	while (fscanf(f,"%04s%04s%04s%04s%04s%04s%04s%04s %02x %x %02x %02x %32s",
			s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],&index,
			&prefix_len,&scope,&flags,dev)==13) {
		if (scope!=0x00)	/* skip non global addr */
			continue;
		if (strcmp(ifname,dev)==0) {
			memset(addr,0,sizeof(addr));
			snprintf(addr,sizeof(addr),"%s:%s:%s:%s:%s:%s:%s:%s",
				s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]);
			inet_pton(AF_INET6,addr,i->srcip6);
			fclose(f);
			return 1;
		}
	}

	fclose(f);
	return 0;
}

static inline void
__intf_base_get(intf_t *i, const char *ifname)
{
	struct ifreq	ifr;
	int		fd,n1;
	u_int		n;

	assert(ifname);
	assert(i);

	memset(&ifr,0,sizeof(ifr));
	assert((fd=socket(AF_INET,SOCK_DGRAM,0))>=0);
	assert((n1=snprintf(ifr.ifr_name,IFNAMSIZ,"%s",ifname))>=0);
	assert((size_t)n1<IFNAMSIZ);

	if (ioctl(fd,SIOCGIFMTU,&ifr)!=0)
		err(1,"failed get mtu for %s interface",ifname);
	else
		i->mtu=ifr.ifr_mtu;

	if (ioctl(fd,SIOCGIFFLAGS,&ifr)!=0)
		err(1,"failed get flags for %s interface",ifname);
	else
		i->flags=ifr.ifr_flags;

	if (ioctl(fd,SIOCGIFHWADDR,&ifr)!=0)
		err(1,"failed get srcmac for %s interface",ifname);
	else
		memcpy(i->srcmac,ifr.ifr_ifru.ifru_hwaddr.sa_data,6);

	/* get source address */
	if (ioctl(fd,SIOCGIFADDR,&ifr)==0) {
		memcpy(i->srcip4,(ifr.ifr_addr.sa_data+2),4);
		++i->support4;
	}
	if (__intf_ipv6_src_get(i,ifname))
		++i->support6;

	if (!i->support6&&!i->support4)	/* ip4 and ip6 not found ! */
		err(1,"failed get srcip4 and srcip6"
			" for %s interface",ifname);

	n=if_nametoindex(ifname);
	if (!n)
		err(1,"failed get ifindex for %s interface",ifname);
	else
		i->index=(int)n;

	assert((n1=snprintf(i->name,sizeof(i->name),"%s",ifname))>=0);
	assert((size_t)n1<sizeof(i->name));
}

static inline void
__intf_gatewayip4_get(intf_t *i, const char *ifname)
{
	char	dev[IFNAMSIZ];
	u_long	dest,gate;
	char	line[1024];
	u_char	okflag;
	FILE	*f;

	assert(ifname);
	assert(i);

	okflag=0;
	if (!(f=fopen("/proc/net/route","r")))
		errx(1,"failed open /proc/net/route for get gatewayip4"
			" for %s interface",ifname);
	if (!(fgets(line,sizeof(line),f)))
		errx(1,"failed get line /proc/net/route for get gatewayip4"
			" for %s interface",ifname);
	while (fgets(line,sizeof(line),f)) {
		if (sscanf(line,"%15s %lx %lx",dev,&dest,&gate)!=3)
			continue;
		if (dest==0) {	/* is way in internet 0.0.0.0 */
			if (strcmp(ifname,dev)==0) {
				gate=ntohl((u_int)gate);
				i->gatewayip4[0]=((u_int)gate>>24)&0xff;
				i->gatewayip4[1]=((u_int)gate>>16)&0xff;
				i->gatewayip4[2]=((u_int)gate>>8)&0xff;
				i->gatewayip4[3]=((u_int)gate&0xff);
				++okflag;
				break;
			}
		}
	}
	fclose(f);

	if (!okflag)
		errx(1,"failed get gatewayip4 for %s interface",ifname);
}

/* solum after get gatewayip4 */
static inline void
__intf_dstmac_get(intf_t *i, const char *ifname)
{
	char	ip[32],hw_type[32];
	char	flags[32],mac[32];
	char	dev[IFNAMSIZ+1];
	char	line[1024];
	u_char	okflag;
	char	mask[32];
	FILE	*f;

	assert(ifname);
	assert(i);

	okflag=0;
	if (!(f=fopen("/proc/net/arp","r")))
		errx(1,"failed open /proc/net/arp for get dstmac"
			" for %s interface",ifname);
	if (!(fgets(line,sizeof(line),f)))
		errx(1,"failed get line /proc/net/arp for get dstmac"
			" for %s interface",ifname);
	while (fgets(line,sizeof(line),f)) {
		struct ether_addr	*tmp1;
		struct in_addr		tmp;

		if (sscanf(line,"%31s %31s %31s %31s %31s %16s",
				ip,hw_type,flags,mac,mask,dev)!=6)
			continue;
		if (strcmp(dev,ifname))
			continue;
		memset(&tmp,0,sizeof(tmp));
		memcpy(&tmp.s_addr,i->gatewayip4,4);
		if (strcmp(ip,inet_ntoa(tmp)))
			continue;
		if (!(tmp1=ether_aton(mac)))
			errx(1,"failed convert mac for get dstmac"
				" for %s interface",ifname);
		memcpy(i->dstmac,tmp1->ether_addr_octet,6);
		++okflag;
	}
	fclose(f);

	if (!okflag)
		errx(1,"failed get dstmac for %s interface",ifname);
}

int
intf_is_network_sendable(intf_t *i)
{
	assert(i);
	assert(i->flags!=0);
	assert(i->mtu!=0);

	if (!(i->flags&IFF_UP))
		return 0;	/* down interface */
	if (i->flags&IFF_LOOPBACK)
		return 0;	/* loopback */
	if (i->flags&IFF_POINTOPOINT)
		return 0;	/* ptp */
	if (i->flags&IFF_SLAVE)
		return 0;	/* slave */
	if (i->flags&IFF_NOARP)
		return 0;	/* noarp */

	if (i->mtu<576)		/* mtu low */
		return 0;

	return 1;
}

static inline int
__intf_need_dstmac(intf_t *i)
{
	assert(i);
	assert(i->flags!=0);

	if (i->flags&IFF_LOOPBACK)
		return 0;
	if (i->flags&IFF_NOARP)
		return 0;

	return 1;
}

void
intfget(intf_t *i, const char *ifname)
{
	__intf_base_get(i,ifname);

	/* to get it doesn't make sense */
	if (__intf_need_dstmac(i)) {
		__intf_gatewayip4_get(i,ifname);
		__intf_dstmac_get(i,ifname);
	}
}

void
intfget_any(intf_t *i)
{
	struct if_nameindex	*ifni,*start;
	u_char			foundflag;

	ifni=start=NULL;
	if (!(ifni=if_nameindex()))
		 err(1,"failed get list interfaces");

	start=ifni;
	foundflag=0;

	for (;ifni->if_name;ifni++) {
		memset(i,0,sizeof(*i));
		intfget(i,ifni->if_name);
		if (intf_is_network_sendable(i)) {
			++foundflag;
			break;
		}
	}

	if_freenameindex(start);

	if (!foundflag)
		 errx(1,"not found sendable interface");
}
