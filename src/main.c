#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include "checksum.h"
#include "tcp.h"
#include "three_packages.h"
#include "utils.h"

#define IP_LEVEL_OFFSET 14
#define TCP_LEVEL_OFFSET 0x22

int main() {
    // TCP_Packet_Header header;
    // memset(&header, 0, sizeof(header));
    // // get_TCP_header_info(pkt1 + 0x22, &header);
    // get_TCP_header_info(pkt1+0x22,&header);
    // struct iphdr* this_iphdr = (struct iphdr*)(pkt1 + 14);

    // /**
    //  * 端口号、序列号、确认号、window、checksum都需要转换字节序
    //  **/
    // struct tcphdr* this_tcphdr =
    //     (struct tcphdr*)(pkt1 + IP_LEVEL_OFFSET + 4 * this_iphdr->ihl);

    // printf("%d\n%d",ntohs(this_tcphdr->source),ntohs(this_tcphdr->dest));
    int manage_tcp_stream_nums = 60000;
    init_hash();
    init_tcp(manage_tcp_stream_nums);

    // debug
    struct iphdr* this_iphdr = (struct iphdr*)(pkt1 + IP_LEVEL_OFFSET);
    int len = htons(this_iphdr->tot_len);  // IP头+TCP头+TCP头的载荷长度
    // end debug

    process_tcp(pkt1 + IP_LEVEL_OFFSET, strlen(pkt1));
    return 0;
}