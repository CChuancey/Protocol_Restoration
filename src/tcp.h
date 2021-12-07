#ifndef __TCP_H__
#define __TCP_H__

#include <arpa/inet.h>
#include <netinet/tcp.h>
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

// 专供process tcp输出log信息
#define show_log(FUN, MSG) \
    { printf("%s:%s\n", FUN, MSG); }

typedef struct skbuff {
    struct skbuff* next;
    struct skbuff* pre;
    void* data;
    uint32_t len;       // data长度
    uint32_t truesize;  //结构体+data长度
    struct tcphdr* headers;
    uint32_t headers_len;
    char fin;
    char rst;
    uint32_t seq;
    uint32_t ack;
} Socket_Buffer;

typedef struct {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int src_addr;
    unsigned int dst_addr;
} Tuple;

typedef struct proc_node {  //回调函数
    void* (*item)();
    struct proc_node* next;
} Proc_node;

typedef struct {
    char state;           //半连接的状态
    unsigned char* data;  //数据包的地址
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t headerLen;
    Socket_Buffer* list;
    Socket_Buffer* listtail;
    uint32_t rmem_alloc;  //分配给list的空间
    uint32_t first_data_seq;  //发送的第一个字节序列号，两个半连接不相同
    uint32_t ordered_count;  //接收的有序数据 EXPSEQ-first_data_seq
    uint32_t offset;     //表示应用层处理的数据的长度？？？？
    uint32_t buffsize;   // 存储data的buffer大小,不等于data的长度
    uint32_t new_count;  // 本次新提供的数据包的长度
    struct tcphdr current_headers;  //本次数据包的头
    uint32_t current_headers_len;   //本次数据包头的长度
} TCP_Half_Stream;

typedef struct TCP_Stream {
    int hash_index;
    Tuple tuple;
    TCP_Half_Stream server;
    TCP_Half_Stream client;

    struct TCP_Stream* next_node;  //一条流在哈希表的位置
    struct TCP_Stream* pre_node;
    struct TCP_Stream* next_time;  //时间链表
    struct TCP_Stream* pre_time;

    struct TCP_Stream* next_free;  // 指向下一个空闲的结点
    int normal;                    //是否是完整的TCP Stream
} TCP_Stream;

typedef struct TCP_Stream_Timeout {
    TCP_Stream* a_tcp;
    struct timeval tv;
    struct TCP_Stream_Timeout* pre;
    struct TCP_Stream_Timeout* next;
} TCP_Stream_Timeout;

#define EXPSEQ (snd->first_data_seq + rcv->ordered_count)

void process_tcp(const unsigned char* data, const int len);
int init_tcp(const int size);  // size为管理的tcp流的上限
#endif