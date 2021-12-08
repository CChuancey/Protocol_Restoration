#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include "capture.h"
#include "checksum.h"
#include "tcp.h"
#include "utils.h"

#define IP_LEVEL_OFFSET 14
#define TCP_LEVEL_OFFSET 0x22

int main() {
    int manage_tcp_stream_nums = 60000;
    init_hash();
    init_tcp(manage_tcp_stream_nums);
    if (caputure_packet_from_file("./doc/1.pcap", process_tcp) == -1)
        return -1;
    release_pcap_resource();
    return 0;
}