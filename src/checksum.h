
#ifndef _NIDS_CHECKSUM_H
#define _NIDS_CHECKSUM_H
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/types.h>

typedef __u_char u_char;
typedef __u_int u_int;
typedef __u_short u_short;

extern u_short ip_fast_csum(u_short* addr, int len);
extern u_short ip_compute_csum(u_short* addr, int len);
extern u_short my_tcp_check(struct tcphdr* ,int, u_int, u_int);

#endif /* _NIDS_CHECKSUM_H */
