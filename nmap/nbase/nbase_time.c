/***********************************************************************
 * nbase_time.c -- Some small time-related utility/compatability       *
 * functions.                                                          * 
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

/* $Id: nbase_time.c,v 1.4 2000/12/07 04:13:17 fyodor Exp $ */

#include "nbase.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#ifdef WIN32
#include <sys/timeb.h>
#include <winsock2.h>
#endif

#ifndef HAVE_USLEEP
void usleep(unsigned long usec) {
#ifdef HAVE_NANOSLEEP
struct timespec ts; 
ts.tv_sec = usec / 1000000; 
ts.tv_nsec = (usec % 1000000) * 1000; 
nanosleep(&ts, NULL);
#else /* Windows style */
 Sleep( usec / 1000 ); 
#endif /* HAVE_NANOSLEEP */
}
#endif

#ifdef WIN32
int gettimeofday(struct timeval *tv, struct timeval *tz)
{
//	time_t ltime;
	struct _timeb timebuffer;

	_ftime( &timebuffer );

	tv->tv_sec = timebuffer.time;
	tv->tv_usec = timebuffer.millitm * 1000;
	return 0;
};

unsigned int sleep(unsigned int seconds)
{
	Sleep(1000*seconds);
	return(0);
};
#endif /* WIN32 */

