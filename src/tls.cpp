#include "tls.h"

static int hash_table_size = 0;
static TLS_Stream** hash_table = NULL;

static int tls_stream_pool_size = 0;
static TLS_Stream* tls_stream_pool = NULL;
static TLS_Stream* free_streams;

/**
 * @brief 初始化TLS的数据结构，类似TCP的初始化，建立一个hash table和stream pool
 *
 * @param size  hash table的大小，与tls相同
 * @return int -1 初始化失败，0 成功
 */
int init_tls(const int size) {
    if (size > HASH_TABLE_MAX_SIZE) {
        fprintf(stderr, "The specified hash table capacity is too large\n");
        return -1;
    } else if (size <= 0) {
        fprintf(stderr, "The specified hash table capacity is invalid\n");
        return -1;
    }
    hash_table_size = size;
    hash_table = (TLS_Stream**)calloc(size, sizeof(TLS_Stream*));
    if (hash_table == NULL) {
        fprintf(stderr, "init failed! no memeory\n");
        return -1;
    }
    tls_stream_pool_size = 3 * size / 4;
    tls_stream_pool =
        (TLS_Stream*)malloc(sizeof(TLS_Stream) * (tls_stream_pool_size + 1));
    if (tls_stream_pool == NULL) {
        fprintf(stderr, "init failed! no memeory\n");
        return -1;
    }
    for (int i = 0; i < tls_stream_pool_size; i++) {
        tls_stream_pool[i].next = &(tls_stream_pool[i + 1]);
    }
    tls_stream_pool[tls_stream_pool_size].next = NULL;
    free_streams = tls_stream_pool;
    return 0;
}

/**
 * @brief 根据hash index找流，tuple是在hash冲突时，流的唯一标识符
 *
 * @param hash_index
 * @param tuple
 * @return TLS_Stream*
 */
static TLS_Stream* find_stream(int hash_index, Tuple* tuple) {
    TLS_Stream* a_tls = NULL;
    for (a_tls = hash_table[hash_index];
         a_tls && (memcpy(&a_tls->tuple, tuple, sizeof(Tuple)));
         a_tls = a_tls->next)
        ;
    return a_tls ? a_tls : NULL;
}

/**
 * @brief 暂定按端口号处理，传的参数四元组为临时处理方案
 *
 * @param data
 * @return true
 * @return false
 */
static bool check_if_it_is_TLS(unsigned char* data, Tuple* tuple) {
    // to do
    if (tuple->dst_port == 443 || tuple->src_port == 443)
        return true;
    return false;
}

static void add_new_tls(Half_TLS_Stream* rcv,
                        unsigned char* data,
                        uint32_t datalen) {
    memset(rcv, 0, sizeof(Half_TLS_Stream));
    rcv->data = data;
    rcv->datalen = datalen;
}

/**
 * @brief
 * 函数处理TLS数据包的函数入口 *
 * @param stream tcp流
 * @param fromclient 上下行
 * @param del   是否删流
 * @return int
 * -2：不是TLS数据包
 * -1：需要将本次提交的数据包过滤
 *  0：需要将本次提交的数据转发
 * >0：本次提交数据包处理的字节数
 */
int process_tls(TCP_Stream* stream, bool fromclient, bool del) {
    TLS_Stream* a_tls = find_stream(stream->hash_index, &stream->tuple);
    unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char));
    if (data == NULL) {
        show_log(__func__, "No Memory");
        abort();
    }
    uint32_t datalen = 0;
    Half_TLS_Stream* snd = NULL;
    Half_TLS_Stream* rcv = NULL;
    if (fromclient) {
        snd = &a_tls->client;
        rcv = &a_tls->server;
        memcpy(data, stream->client.data, stream->client.ordered_count);
        datalen = stream->client.ordered_count;
    } else {
        snd = &a_tls->server;
        rcv = &a_tls->client;
        memcpy(data, stream->server.data, stream->server.ordered_count);
        datalen = stream->server.ordered_count;
    }
    if (a_tls) {  //流已存在
        // 设计处理状态
    } else {
    }
}