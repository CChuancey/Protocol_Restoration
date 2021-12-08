#ifndef __TLS_H__
#define __TLS_H__
#include "tcp.h"

#define DEFAULT_TLS_PACKET_LEN 65536

typedef struct half_tls_stream {
    unsigned char* data;
    int datalen;
    int state;
} Half_TLS_Stream;

typedef struct tls_stream {
    struct tls_stream* pre;
    struct tls_stream* next;
    Tuple tuple;     // TCP四元组
    int hash_index;  // hash索引值
    Half_TLS_Stream server;
    Half_TLS_Stream client;
} TLS_Stream;

#endif