/***********************************************************************
 * nbase_winconfig.h -- Since the Windows port is currently eschewing  *
 * autoconf-style configure scripts, nbase_winconfig.h contains the    *
 * platform-specific definitions for Windows and is used as a          *
 * replacement for nbase_config.h                                      *
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

/* $Id: nbase_winconfig.h,v 1.9 2002/12/18 08:41:38 fyodor Exp $ */

#ifndef NBASE_WINCONFIG_H
#define NBASE_WINCONFIG_H

/* It doesn't really have strucct IP, but we use a different one instead
	of the one that comes with Nmap */
#define HAVE_STRUCT_IP 1
#define HAVE_STRUCT_ICMP 1
#define HAVE_IP_IP_SUM 1
#define STDC_HEADERS 1
#define HAVE_STRING_H 1
#define HAVE_MEMCPY 1
#define HAVE_STRERROR 1
#define HAVE_SYS_SOCKIO_H 1
#define HAVE_ERRNO_H 1
/* #define HAVE_STRCASESTR 1 */
#define HAVE_STRCASECMP 1
#define HAVE_NETINET_IN_SYSTEM_H 1
#define HAVE_NETINET_IF_ETHER_H 1
#define HAVE_SYS_STAT_H 1

#define HAVE_SNPRINTF 1
#define HAVE_VASPRINTF 1
#define HAVE_VSNPRINTF 1

#define SIZEOF_CHAR 1
#define SIZEOF_SHORT 2
#define SIZEOF_INT 4
#define SIZEOF_LONG 4

#define HAVE_AF_INET6 1
/* #undef HAVE_SOCKADDR_STORAGE */

#endif /* NBASE_WINCONFIG_H */
