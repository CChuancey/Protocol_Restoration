#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include "capture.h"
#include "checksum.h"
#include "tcp.h"
#include "tls.h"
#include "trie.h"
#include "utils.h"

#define IP_LEVEL_OFFSET 14
#define TCP_LEVEL_OFFSET 0x22

int main() {
    int manage_tcp_stream_nums = 60000;
    init_hash();
    init_tcp(manage_tcp_stream_nums);
    register_tcp_callbk(process_tls);
    pthread_t tid;

    // if (pthread_create(&tid, NULL, check_sql_server_status, NULL) == -1) {
    //     fprintf(stderr, "thread create error\n");
    //     return -1;
    // }
    if (caputure_packet_from_file("/home/chuancey/project/src/doc/tls1.2.pcap",
                                  process_tcp) == -1)
        return -1;
    // release_pcap_resource();
    // release_sql_resource(sql);
    // release_trie_resource();
    // while (1) {
    //     sleep(1);
    // }

    return 0;
}