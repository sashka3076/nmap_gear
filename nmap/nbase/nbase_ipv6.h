
/***********************************************************************
 * nbase_ipv6.h -- IPv6 portability classes and structures             *
 * These were written by fyodor@insecure.org .                         *
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

/* $Id: nbase_ipv6.h,v 1.4 2002/12/18 08:41:38 fyodor Exp $ */

#ifndef NBASE_IPV6_H
#define NBASE_IPV6_H

#ifndef HAVE_AF_INET6
#define AF_INET6 10
#define PF_INET6 10
#endif /* HAVE_AF_INET6 */
#ifndef HAVE_INET_PTON
/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int inet_pton(int af, const char *src, void *dst);
#endif /* HAVE_INET_PTON */

#ifndef HAVE_INET_NTOP
/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char * inet_ntop(int af, const void *src, char *dst, size_t size);
#endif /* HAVE_INET_NTOP */

#ifndef HAVE_SOCKADDR_STORAGE
     /* Just needs to be big enough to hold sockaddr_in or
	sockaddr_in6.  I should really align it at 64 bits, but 32 is
	probably fine as hosts that actually want to store a
	sockaddr_in6 in here should already have this defined (see
	RFC2355). */
struct sockaddr_storage {
	u32 padding[32];
}; 
#endif /* SOCKADDR_STORAGE */

#if !HAVE_GETNAMEINFO || !HAVE_GETADDRINFO
#if !defined(EAI_MEMORY)
#define EAI_ADDRFAMILY   1      /* address family for hostname not supported */
#define EAI_AGAIN        2      /* temporary failure in name resolution */
#define EAI_BADFLAGS     3      /* invalid value for ai_flags */
#define EAI_FAIL         4      /* non-recoverable failure in name resolution */
#define EAI_FAMILY       5      /* ai_family not supported */
#define EAI_MEMORY       6      /* memory allocation failure */
#define EAI_NODATA       7      /* no address associated with hostname */
#define EAI_NONAME       8      /* hostname nor servname provided, or not known */
#define EAI_SERVICE      9      /* servname not supported for ai_socktype */
#define EAI_SOCKTYPE    10      /* ai_socktype not supported */
#define EAI_SYSTEM      11      /* system error returned in errno */
#define EAI_BADHINTS    12
#define EAI_PROTOCOL    13
#define EAI_MAX         14
#endif /* EAI_MEMORY */
#endif /* !HAVE_GETNAMEINFO || !HAVE_GETADDRINFO */

#if !HAVE_GETNAMEINFO
/* This replacement version is *NOT* a full implementation by any
   stretch of the imagination */
/* getnameinfo flags */
#if !defined(NI_NAMEREQD)
#define NI_NOFQDN 8
#define NI_NUMERICHOST 16
#define NI_NAMEREQD 32
#define NI_NUMERICSERV 64
#define NI_DGRAM 128
#endif

struct sockaddr;
int getnameinfo(const struct sockaddr *sa, size_t salen,
		char *host, size_t hostlen,
		char *serv, size_t servlen, int flags);
#endif /* !HAVE_GETNAMEINFO */

#if !HAVE_GETADDRINFO
/* This replacement version is *NOT* a full implementation by any
   stretch of the imagination */
struct addrinfo {
  int ai_flags;      /*  AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
  int ai_family;    /* PF_xxx */
  int ai_socktype;  /* SOCK_xxx */
  int ai_protocol;  /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
  size_t ai_addrlen;   /* length of ai_addr */
  char *ai_canonname; /* canonical name for nodename */
  struct sockaddr  *ai_addr; /* binary address */
  struct  addrinfo  *ai_next; /* next structure in linked list */
};

/* getaddrinfo Flags */
#if !defined(AI_PASSIVE) || !defined(AI_CANONNAME) || !defined(AI_NUMERICHOST)
#define AI_PASSIVE 1
#define AI_CANONNAME 2
#define AI_NUMERICHOST 4
#endif

void freeaddrinfo(struct addrinfo *res);
int getaddrinfo(const char *node, const char *service, 
		const struct addrinfo *hints, struct addrinfo **res);

#endif /* !HAVE_GETADDRINFO */

#ifndef HAVE_GAI_STRERROR
const char *gai_strerror(int errcode);
#endif


#endif /* NBASE_IPV6_H */
