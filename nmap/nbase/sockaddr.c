#include "nbase_config.h"
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

void main(void) {
	    struct sockaddr_in sa;
	        char hbuf[256];
		    int error;

		        sa.sin_family = AF_INET;
			    sa.sin_port = 0;
			        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
#ifdef SIN6_LEN
				    sa.sin_len = sizeof(sa);
#endif

				        error = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
							                        hbuf, 256, NULL, 0,
										                        NI_NUMERICHOST);
					    if (error) {
						            exit(1);
							        } else {
									        exit(0);
										    }
}
