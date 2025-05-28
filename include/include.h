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

#ifndef __RAW_U_INCLUDE_H
#define __RAW_U_INCLUDE_H

#include "../config.h"

#include <sys/types.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdnoreturn.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netdb.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <poll.h>
#include <limits.h>

#define __RAW_U_VERSION PACKAGE_VERSION

#define startmsg() do { \
	char date[512]; \
	printf("Running %s %s at %s\n",__FILE_NAME__, \
		__RAW_U_VERSION,strdate(date,sizeof(date))); \
	} while(0);

#define endmsg(_st,_et) do { \
	char diff[512]; \
	printf("Ending %s at %s and clearing the memory\n", \
		__FILE_NAME__,timediff(_st,_et,diff,sizeof(diff))); \
	} while(0);

#define isroot() do {\
	if (geteuid()) \
		errx(1,"raw sockets on UNIX only sudo"); \
	} while (0);

#endif






