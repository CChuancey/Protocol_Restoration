#include "capture.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>

static fun callbk;
static char errbuff[BUFSIZ];
static pcap_t* session;

void packet_handler(unsigned char* user,
                    const struct pcap_pkthdr* pkthdr,
                    const unsigned char* packet) {
    const struct ether_header* ethernet_header = (struct ether_header*)packet;
    const struct iphdr* ip_header =
        (struct iphdr*)(packet + sizeof(struct ether_header));
    //只要TCP包
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP &&
        ip_header->protocol == IPPROTO_TCP) {
        // printf("packet size:%u\n", ntohs(ip_header->tot_len));
        callbk(packet + sizeof(struct ether_header),
               0);  //第二个skblen值待定
    }
}

int caputure_packet_from_file(const char* pcap_file, fun callback) {
    session = pcap_open_offline(pcap_file, errbuff);
    if (session == NULL) {
        fprintf(stderr, "pcap_open_offline:%s\n", errbuff);
        return -1;
    }
    callbk = callback;  //设置回调函数
    int loop_ret = pcap_loop(session, -1, packet_handler, NULL);
    if (loop_ret == -1) {
        fprintf(stderr, "pcap loop err:%s\n", pcap_geterr);
        return -1;
    } else if (loop_ret == -2) {
        fprintf(stderr,
                "an error occurs because the loop terminated due to a call to "
                "pcap_break‐loop() before any packets were processed. \n");
        return -1;
    }
    return 0;
}

void release_pcap_resource() {
    pcap_close(session);
}
