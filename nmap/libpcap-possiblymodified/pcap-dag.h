/*
 * pcap-dag.c: Packet capture interface for Endace DAG card.
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is only needed when compiling in the DAG card code
 * at the same time as another type of device.
 *
 * Author: Richard Littin, Sean Irvine ({richard,sean}@reeltwo.com)
 *
 * @(#) $Header: /CVS/nmap/libpcap-possiblymodified/pcap-dag.h,v 1.1 2004/08/01 05:34:47 fyodor Exp $ (LBL)
 */

pcap_t *dag_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf);

