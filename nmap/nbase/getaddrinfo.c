/***********************************************************************
 * getaddrinfo.c -- A **PARTIAL** implementation of the getaddrinfo(3) *
 * hostname resolution call.  In particular, IPv6 is not    *
 * supported and neither are some of the flags.  Service "names" are   *
 * always returned as port numbers.                                    *
 *                                                                     *
 ***********************************************************************
 *                                                                     *
 *  Many of the files contained in libnbase are compatability          *
 *  functions written by others.  License conditions for those files   *
 *  may vary and is generally included at the top of the files.   Be   *
 *  sure to read that information before you redistribute or           *
 *  incorporate parts of those files into your software.               *
 *                                                                     *   
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port libnbase to new platforms, fix *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *                                                                     *
 ***********************************************************************/

/* $Id: getaddrinfo.c,v 1.1 2002/08/28 07:15:32 fyodor Exp $ */

#include "nbase.h"

#include <stdio.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <assert.h>


#ifndef HAVE_GAI_STRERROR
const char *gai_strerror(int errcode) {
  static char customerr[64];
  switch (errcode) {
  case EAI_FAMILY:
    return "ai_family not supported";
  case EAI_NODATA:
    return "no address associated with hostname";
  case EAI_NONAME:
    return "hostname nor servname provided, or not known";
  default:
    snprintf(customerr, sizeof(customerr), "unknown error (%d)", errcode);
    return "unknown error.";
  }
  return NULL; /* unreached */
}
#endif

#ifndef HAVE_GETADDRINFO
void freeaddrinfo(struct addrinfo *res) {
  struct addrinfo *next;
  
  do {
    next = res->ai_next;
    free(res);
  } while ((res = next) != NULL);
}

/* Allocates and initializes a new AI structure with the port and IPv4
   address specified in network byte order */
static struct addrinfo *new_ai(unsigned short portno, u32 addr)
{
	struct addrinfo *ai;

	ai = (struct addrinfo *) malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
	assert(ai);
	
	memset(ai, 0, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
	
	ai->ai_family = AF_INET;
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr = (struct sockaddr *)(ai + 1);
	ai->ai_addr->sa_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
	ai->ai_addr->sa_len = ai->ai_addrlen;
#endif
	((struct sockaddr_in *)(ai)->ai_addr)->sin_port = portno;
	((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;
	
	return(ai);
}


int getaddrinfo(const char *node, const char *service, 
		const struct addrinfo *hints, struct addrinfo **res) {

  struct addrinfo *cur, *prev = NULL;
  struct hostent *he;
  struct in_addr ip;
  unsigned short portno;
  int i;
  
  if (service)
    portno = htons(atoi(service));
  else
    portno = 0;
  
  if (hints && hints->ai_flags & AI_PASSIVE) {
    *res = new_ai(portno, htonl(0x00000000));
    return 0;
  }
  
  if (!node) {
    *res = new_ai(portno, htonl(0x7f000001));
    return 0;
  }
  
  if (inet_aton(node, &ip)) {
    *res = new_ai(portno, ip.s_addr);
    return 0;
  }
  
  he = gethostbyname(node);
  if (he && he->h_addr_list[0]) {
    for (i = 0; he->h_addr_list[i]; i++) {
      cur = new_ai(portno, ((struct in_addr *)he->h_addr_list[i])->s_addr);

      if (prev)
	prev->ai_next = cur;
      else
	*res = cur;
      
      prev = cur;
    }
    return 0;
  }
  
  return EAI_NODATA;
}
#endif /* HAVE_GETADDRINFO */
