
/***********************************************************************
 * nbase.h -- The main include file exposing the external API for      *
 * libnbase, a library of base (often compatability) routines.         *
 * Programs using libnbase can guarantee the availability of functions *
 * like (v)snprintf and inet_aton.  This library also provides         *
 * consistency and extended features for some functions.  It was       *
 * originally written for use in the Nmap Security Scanner             *
 * ( http://www.insecure.org/nmap/ ).                                  *
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

/* $Id: nbase.h,v 1.23 2002/09/19 02:24:30 fyodor Exp $ */

#ifndef NBASE_H
#define NBASE_H

/* NOTE -- libnbase offers the following features that you should probably
 * be aware of:
 *
 * * 'inline' is defined to what is neccessary for the C compiler being
 *   used (which may be nothing)
 *
 * * snprintf, inet_aton, inet_pton, inet_aton, memcpy, and bzero are 
 *   provided if you don't have them (prototypes for these are 
 *   included either way).
 *
 * * WORDS_BIGENDIAN is defined if platform is big endian
 *
 * * Definitions included which give the operating system type.  They
 *   will generally be one of the following: LINUX, FREEBSD, NETBSD,
 *   OPENBSD, SOLARIS, SUNOS, BSDI, IRIX, NETBSD
 *
 * * Insures that GNU getopt_* functions exist (such as getopt_long_only
 *
 * * Various string functions such as Strncpy() and strcasestr() see protos 
 *   for more info.
 *
 * * IPv6 structures like 'sockaddr_storage' are provided if they do
 *   not already exist.
 */

#if HAVE_CONFIG_H
#include "nbase_config.h"
#else
#ifdef WIN32
#include "nbase_winconfig.h"
#endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

#ifdef WIN32
#include "mswin32\winclude.h"
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 2048
#endif

#ifndef HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif


#include <stdarg.h>


/* Insure memcpy() and bzero() are available */
#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy((s), (d), (n))
#endif

#ifndef HAVE_BZERO
#define bzero(s, n) memset((s), 0, (n))
#endif

/* Integer widths */
#if (SIZEOF_CHAR == 1)
typedef unsigned char u8;
#else
typedef u_int8_t u8;
#endif

#if (SIZEOF_SHORT == 2)
typedef unsigned short u16;
typedef short s16;
#elif (SIZEOF_CHAR == 2)
typedef unsigned char u16;
typedef char s16;
#else
typedef u_int16_t u16;
typedef int16_t s16;
#endif

#if (SIZEOF_SHORT == 4)
typedef unsigned short u32;
typedef short s32;
#elif (SIZEOF_INT == 4)
typedef unsigned int u32;
typedef int s32;
#elif (SIZEOF_LONG == 4)
typedef unsigned long u32;
typedef long s32;
#else
typedef u_int32_t u32;
typedef int32_t s32;
#endif

/* sprintf family */
#if !defined(HAVE_SNPRINTF)
int snprintf (char *str, size_t sz, const char *format, ...)
     __attribute__ ((format (printf, 3, 4)));
#endif

#if !defined(HAVE_VSNPRINTF)
int vsnprintf (char *str, size_t sz, const char *format, va_list ap)
     __attribute__((format (printf, 3, 0)));
#endif

#if !defined(HAVE_ASPRINTF)
int asprintf (char **ret, const char *format, ...)
     __attribute__ ((format (printf, 2, 3)));
#endif

#if !defined(HAVE_VASPRINTF)
int vasprintf (char **ret, const char *format, va_list ap)
     __attribute__((format (printf, 2, 0)));
#endif

#if !defined(HAVE_ASNPRINTF)
int asnprintf (char **ret, size_t max_sz, const char *format, ...)
     __attribute__ ((format (printf, 3, 4)));
#endif

#if !defined(HAVE_VASNPRINTF)
int vasnprintf (char **ret, size_t max_sz, const char *format, va_list ap)
     __attribute__((format (printf, 3, 0)));
#endif

/* GNU getopt replacements ... Anyone have a BSD licensed version of these? */
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
/* The next half-dozen lines are from gcc-2.95 ... -Fyodor */
/* Include getopt.h for the sake of getopt_long.
   We don't need the declaration of getopt, and it could conflict
   with something from a system header file, so effectively nullify that.  */
#define getopt getopt_loser
#include "getopt.h"
#undef getopt
#endif /* HAVE_GETOPT_H */

/* The usleep() function is important as well */
#ifndef HAVE_USLEEP
#if defined( HAVE_NANOSLEEP) || defined(WIN32)
void usleep(unsigned long usec);
#endif
#endif

/* More Windows-specific stuff */
#ifdef WIN32

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define WIN32_LEAN_AND_MEAN /* Whatever this means! From winclude.h*/

/* Apparently Windows doesn't have S_ISDIR */
#ifndef S_ISDIR
#define S_ISDIR(m)      (((m) & _S_IFMT) == _S_IFDIR)
#endif

#define stat _stat // wtf was ms thinking?
#define execve _execve
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp


#endif /* WIN32 */

/* Apparently Windows doesn't like /dev/null */
#ifdef WIN32
#define DEVNULL "NUL"
#else
#define DEVNULL "/dev/null"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/***************** String functions -- See nbase_str.c ******************/
/* I modified this conditional because !@# Redhat does not easily provide
   the prototype even though the function exists */
#if !defined(HAVE_STRCASESTR) || defined(LINUX)
/* strcasestr is like strstr() except case insensitive */
char *strcasestr(const char *haystack, const char *pneedle);
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2);
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(const char *s1, const char *s2, size_t n);
#endif

#ifndef HAVE_GETTIMEOFDAY
int gettimeofday(struct timeval *tv, struct timeval *tz);
#endif

#ifndef HAVE_SLEEP
unsigned int sleep(unsigned int seconds);
#endif

#ifndef HAVE_INET_ATON
struct in_addr;
int inet_aton(const char *cp, struct in_addr *addr);
#endif

/* Strncpy is like strcpy() except it ALWAYS zero-terminates, even if
   it must truncate */
int Strncpy(char *dest, const char *src, size_t n);

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#include "nbase_ipv6.h"

#ifdef __cplusplus
}
#endif

#endif /* NBASE_H */
