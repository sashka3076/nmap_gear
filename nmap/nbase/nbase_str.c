
/***********************************************************************/
/* nbase_str.c -- string related functings in the nbase library.       *
 * These were written by fyodor@insecure.org .                         *
 *                                                                     *
 ***********************************************************************
 *                                                                     *
 *  Many of the files contained in libnbase are compatability          *
 *  functions written by others.  License conditions for those files   *
 *  may vary and is generally included at the top of the files.   Be   *
 *  sure to read that information before you redistribute or           *
 *  contents of those files.                                           *
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

/* $Id: nbase_str.c,v 1.1 2000/10/15 07:16:22 fyodor Exp $ */

#include "nbase.h"
#include <string.h>

#ifndef HAVE_STRCASESTR
char *strcasestr(char *haystack, char *pneedle) {
char buf[512];
unsigned int needlelen;
char *needle, *p, *q, *foundto;

/* Should crash if !pneedle -- this is OK */
if (!*pneedle) return haystack;
if (!haystack) return NULL;

needlelen = strlen(pneedle);
 if (needlelen >= sizeof(buf)) {
   needle = (char *) malloc(needlelen + 1);
 } else needle = buf;
 p = pneedle; q = needle;
 while((*q++ = tolower(*p++)))
   ;
 p = haystack - 1; foundto = needle;
 while(*++p) {
   if(tolower(*p) == *foundto) {
     if(!*++foundto) {
       /* Yeah, we found it */
       if (needlelen >= sizeof(buf))
         free(needle);
       return p - needlelen + 1;
     }
   } else foundto = needle;
 }
 if (needlelen >= sizeof(buf))
   free(needle);
 return NULL;
}
#endif

int Strncpy(char *dest, const char *src, size_t n) {
  strncpy(dest, src, n);
  if (dest[n-1] == '\0')
    return 0;
  dest[n-1] = '\0';
  return -1;
}
