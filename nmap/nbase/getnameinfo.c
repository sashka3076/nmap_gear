/***********************************************************************
 * getnameinfo.c -- A **PARTIAL** implementation of the getnameinfo(3) *
 * host resolution call.  In particular, IPv6 is not supported and     *
 * neither are some of the flags.  Service "names" are always returned *
 * as decimal port numbers.                                            *
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

/* $Id: getnameinfo.c,v 1.1 2002/08/28 07:15:32 fyodor Exp $ */
#include "nbase.h"

#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <assert.h>
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


int getnameinfo(const struct sockaddr *sa, size_t salen,
		char *host, size_t hostlen,
		char *serv, size_t servlen, int flags) {
  
  struct sockaddr_in *sin = (struct sockaddr_in *)sa;
  struct hostent *he;
  
  if (sin->sin_family != AF_INET || salen != sizeof(struct sockaddr_in))
    return EAI_FAMILY;
  
  if (serv != NULL) {
    snprintf(serv, servlen, "%d", ntohs(sin->sin_port));
    return 0;
  }
  
  if (host) {
    if (flags & NI_NUMERICHOST) {    
      Strncpy(host, inet_ntoa(sin->sin_addr), hostlen);
      return 0;
    } else {
      he = gethostbyaddr((char *)&sin->sin_addr, sizeof(struct in_addr), 
			 AF_INET);
      if (he == NULL) {      
	if (flags & NI_NAMEREQD)
	  return EAI_NONAME;
	
	Strncpy(host, inet_ntoa(sin->sin_addr), hostlen);
	return 0;
      }
      
      assert(he->h_name);
      Strncpy(host, he->h_name, hostlen);
      return 0;
    }
  }
  return 0;
}
