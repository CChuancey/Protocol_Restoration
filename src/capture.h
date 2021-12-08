#ifndef __CAPTURE_H__
#define __CAPTURE_H__

typedef void (*fun)(const unsigned char*);

extern int caputure_packet_from_file(const char* pcap_file, fun callbackfun);
extern void release_pcap_resource();

#endif