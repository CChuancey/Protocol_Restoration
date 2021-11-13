#include "tcp.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include "checksum.h"

// TCP维护的变量
// hash table
TCP_Stream** hash_table = NULL;
int hash_table_size = 0;

//追踪的流
TCP_Stream* tcp_stream_pool = NULL;
int tcp_stream_pool_size = 0;

//空闲的空间
TCP_Stream* free_streams = NULL;

// 核心函数，处理TCP报文的函数
void process_tcp(const unsigned char* data, const int skblen) {  // skblen?
    struct iphdr* ipheader = (struct iphdr*)data;
    struct tcphdr* tcpheader = (struct tcphdr*)(data + ipheader->ihl * 4);

    //检查TCP报文是否正常
    // 长度
    unsigned int ip_packet_len = ntohs(ipheader->tot_len);  // ip报文的总长度
    if (ip_packet_len < 4 * ipheader->ihl + sizeof(struct tcphdr)) {
        // 数据包长度异常
        show_log(__func__, "ip packet length is invaild!");
        // free(data);
        return;
    }
    // ip地址以及端口号不能为0
    if ((ipheader->saddr | ipheader->daddr) == 0) {
        show_log(__func__, "ip address is invalid!");
        // free(data);
        return;
    }
    if ((tcpheader->source | tcpheader->dest) == 0) {
        show_log(__func__, "port number is invalid!");
        // free
        return;
    }
    printf("packet size:%u\n",ntohs(ipheader->tot_len));
    //数据包的校验和
    if (my_tcp_check(tcpheader, ip_packet_len - 4 * ipheader->ihl,
                     ipheader->saddr, ipheader->daddr)) {
        show_log(__func__, "tcp check sum error!");
        // free
        return;
    }
#ifdef _DEBUG
    puts("tcp process function:data packet ok!");
#endif

    //-----端口匹配------
    // to do 读取前缀树规则（匹配IP、端口号）

    //三次握手、四次挥手、数据包交付
    
}

//初始化HashTable、stream_pool、free_streams
int init_tcp(const int size) {
    if (size > HASH_TABLE_MAX_SIZE) {  // TCP流的上限
        fprintf(stderr, "The specified hash table capacity is too large\n");
        return -1;
    } else if (size <= 0) {
        fprintf(stderr, "The specified hash table capacity is invalid\n");
        return -1;
    }
    hash_table_size = size;
    hash_table = calloc(size, sizeof(TCP_Stream*));
    if (hash_table == NULL) {
        fprintf(stderr, "init failed! no memeory\n");
        return -1;
    }

    tcp_stream_pool_size = 3 * size / 4;
    tcp_stream_pool =
        (TCP_Stream*)malloc(sizeof(TCP_Stream) * (tcp_stream_pool_size + 1));
    if (tcp_stream_pool == NULL) {
        fprintf(stderr, "init failed! no memeory\n");
        return -1;
    }
    for (int i = 0; i < tcp_stream_pool_size; i++) {
        tcp_stream_pool[i].next_node = &(tcp_stream_pool[i + 1]);
    }
    tcp_stream_pool[tcp_stream_pool_size].next_node = NULL;
    free_streams = tcp_stream_pool;
    init_hash();
    return 0;
}

void get_TCP_header_info(const unsigned char* start,
                         TCP_Packet_Header* header) {
    printf("0x%x\n", start[0]);
    header->srcPort = ntohs(*(uint16_t*)(start + SRC_PORT_OFFSET));
    header->dstPort = ntohs(*(uint16_t*)(start + DST_PORT_OFFSET));
    header->seqNum = ntohl(*(uint32_t*)(start + SEQ_NUM_OFFSET));
    header->ackNum = ntohl(*(uint32_t*)(start + ACK_NUM_OFFSET));
    header->headerLen = (((*(start + HEADER_LEN_OFFSET)) & 0xf0) >> 4) * 4;
    header->flag = *(start + FLAG_OFFSET);
    header->windowSize = ntohs(*(uint16_t*)(start + WINDOW_SIZE_OFFSET));
    header->checkSum = ntohs(*(uint16_t*)(start + CHECKSUM_OFFET));
}
