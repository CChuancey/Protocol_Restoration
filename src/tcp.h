#ifndef __TCP_H__
#define __TCP_H__

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include "hash.h"

#define HASH_TABLE_MAX_SIZE 60000

#define SRC_PORT_OFFSET 0
#define DST_PORT_OFFSET 2
#define SEQ_NUM_OFFSET 4
#define ACK_NUM_OFFSET 8
#define HEADER_LEN_OFFSET 12
#define FLAG_OFFSET 13
#define WINDOW_SIZE_OFFSET 14
#define CHECKSUM_OFFET 16

// 专攻process tcp输出log信息
#define show_log(FUN, MSG) \
    { printf("%s:%s\n", FUN, MSG); }

typedef struct {
} Packet_Buffer;

typedef enum {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
} TCP_Flags;

typedef struct {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t headerLen;
    TCP_Flags flag;
    uint16_t windowSize;
    uint16_t checkSum;
} TCP_Packet_Header;

typedef struct {
    char state;  //半连接的状态
    char* data;  //数据包的地址
    TCP_Packet_Header header;
    Packet_Buffer* list;
    Packet_Buffer* end_pointer;
} TCP_Half_Stream;

typedef struct TCP_Stream {
    int hash_index;
    TCP_Half_Stream server;
    TCP_Half_Stream client;

    struct TCP_Stream* next_node;  //一条流在哈希表的位置
    struct TCP_Stream* pre_node;
    struct TCP_Stream* next_time;  //时间链表
    struct TCP_Stream* pre_time;

} TCP_Stream;

typedef struct TCP_Stream_Timeout {
    TCP_Stream* a_tcp;
    struct timeval tv;
    struct TCP_Stream_Timeout* pre;
    struct TCP_Stream_Timeout* next;
} TCP_Stream_Timeout;

void get_TCP_header_info(const unsigned char* start, TCP_Packet_Header* header);
void process_tcp(const unsigned char* data, const int len);
int init_tcp(const int size);  // size为管理的tcp流的上限
#endif