/***********************************************************************/
/* strcasecmp.c -- strcasecmp and strncasecmp for systems              *
 *(like Windows) which do not already have them.
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

/* $Id: strcasecmp.c,v 1.5 2002/08/27 21:08:21 fyodor Exp $ */

#if !defined(HAVE_STRCASECMP) || !defined(HAVE_STRNCASECMP)
#include <stdlib.h>
#include <string.h>
#include "nbase.h"
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2)
{
  int ret;
  
  char *cp1,*cp2;
  int i=0;
  
  cp1=malloc(strlen(s1)+1);
  memset(cp1,0,strlen(s1)+1);
  memcpy(cp1,s1,strlen(s1));
  for (i=0; cp1[i]>0; i++)
    {
      if ('a' <= cp1[i] && cp1[i] <= 'z')
	cp1[i] -= 32;
    }
  
  cp2=malloc(strlen(s2)+1);
  memset(cp2,0,strlen(s2)+1);
  memcpy(cp2,s2,strlen(s2));
  for (i=0; cp2[i]>0; i++)
    {
      if ('a' <= cp2[i] && cp2[i] <= 'z')
	cp2[i] -= 32;
    }

  ret=strcmp(cp1,cp2);
  
  free(cp1);
  free(cp2);
  return ret;
}
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(const char *s1, const char *s2, size_t n)
{
  int ret;
  char *cp1,*cp2;
  int i=0;
  
  cp1= (char *) malloc(strlen(s1)+1);
  memset(cp1,0,strlen(s1)+1);
  memcpy(cp1,s1,strlen(s1));
  for (i=0; cp1[i]>0; i++)
    {
      if ('a' <= cp1[i] && cp1[i] <= 'z')
	cp1[i] -= 32;
    }
  
  cp2= (char *) malloc(strlen(s2)+1);
  memset(cp2,0,strlen(s2)+1);
  memcpy(cp2,s2,strlen(s2));
  for (i=0; cp2[i]>0; i++)
    {
      if ('a' <= cp2[i] && cp2[i] <= 'z')
	cp2[i] -= 32;
    }
  
  ret=strncmp(cp1,cp2,n);
  free(cp1);
  free(cp2);
  return ret;
}
#endif
