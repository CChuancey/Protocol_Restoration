#ifndef __TLS_H__
#define __TLS_H__
#include <openssl/objects.h>
#include "tcp.h"

#define DEFAULT_TLS_PACKET_LEN 65536
#define DATE_LEN 128
#define MAX_LENGTH 1024
#define ENTRY_DEPTH 10

typedef enum {
    HELLO_REQUEST = 0x00,
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    CERTIFICATE = 0x0b,
    SERVER_KEY_EXCHANGE = 0x0c,
    CERTIFICATE_REQUEST = 0x0d,
    SERVER_DONE = 0x0e,
    CERTIFICATE_VERIFY = 0x0f,
    CLIENT_KEY_EXCHANGE = 0x10,
    FINISHED = 0x14
} HAND_SHAKE_PROTOCOL;

// 根据nid，设定枚举值，具体查man OBJ_obj2nid中的Notes，在objects.h中有定义
typedef enum {
    COMMONNAME = NID_commonName,
    COUNTRYNAME,
    LOCALITYNAME,
    STATEORPROVINCENAME,
    ORGANIZATIONNAME,
    ORGANIZATIONUNITNAME,
} Name_Entry;

int process_tls(TCP_Stream* stream, bool fromclient, bool del);
static inline void ntoh(const unsigned char* src, uint32_t* dst) {
    *dst = src[0] << 16;
    *dst += src[1] << 8;
    *dst += src[2];
}

#endif