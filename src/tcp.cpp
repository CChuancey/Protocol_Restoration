#include "tcp.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include "checksum.h"
#include "hash.h"
#include "utils.h"

// TCP维护的变量
// hash table
static TCP_Stream** hash_table = NULL;
static int hash_table_size = 0;  //值在init tcp中设定

//追踪的流
TCP_Stream* tcp_stream_pool = NULL;
static int tcp_stream_pool_size = 0;  // 值在init tcp中设定
static int tcp_num = 0;

//空闲的空间
static TCP_Stream* free_streams = NULL;

// 所有注册的回调函数链表
Proc_node* pnode = NULL;

// 超时链表
TCP_Stream_Timeout* tcp_timeouts = NULL;

// 时序链表
TCP_Stream* tcp_latest = NULL;
TCP_Stream* tcp_oldest = NULL;

void register_tcp_callbk(TCP_Fun fun) {
    // 先检查是否已经存在
    for (Proc_node* node = pnode; node; node = node->next) {
        if (node->fun == fun) {
            return;
        }
    }
    // 头插法将回调函数插入到链表头部
    Proc_node* nwnode = (Proc_node*)malloc(sizeof(Proc_node));
    nwnode->fun = fun;
    nwnode->next = pnode;
    pnode = nwnode;
}

void unregister_tcp_callbk(TCP_Fun fun) {
    Proc_node* pre = NULL;
    for (Proc_node* node = pnode; node; node = node->next) {
        if (fun == node->fun) {
            if (pre) {
                pre->next = node->next;
            } else {
                pnode = node->next;
            }
            free(node);
            return;
        }
        pre = node;
    }
}

static int mk_hash_index(Tuple* tuple) {
    int hash = mkhash(tuple->src_addr, tuple->src_port, tuple->dst_addr,
                      tuple->dst_port);
    return hash % hash_table_size;
}

static void generate_tuple(Tuple* tuple,
                           struct iphdr* ipheader,
                           struct tcphdr* tcpheader,
                           int fromclient) {
    if (fromclient) {
        tuple->src_addr = ntohl(ipheader->saddr);
        tuple->src_port = ntohs(tcpheader->source);
        tuple->dst_addr = ntohl(ipheader->daddr);
        tuple->dst_port = ntohs(tcpheader->dest);
    } else {
        tuple->src_addr = ntohl(ipheader->daddr);
        tuple->src_port = ntohs(tcpheader->dest);
        tuple->dst_addr = ntohl(ipheader->saddr);
        tuple->dst_port = ntohs(tcpheader->source);
    }
}

// 不同的流之间需要PV 操作
static void add_closing_timeout_tcp_stream(TCP_Stream* stream) {
    TCP_Stream_Timeout* new_timeout_tcp =
        (TCP_Stream_Timeout*)malloc(sizeof(TCP_Stream_Timeout));
    new_timeout_tcp->a_tcp = stream;
    new_timeout_tcp->sec = time(NULL) + 120;
    new_timeout_tcp->pre = NULL;
    for (TCP_Stream_Timeout* p = new_timeout_tcp->next = tcp_timeouts; p;
         new_timeout_tcp->next = p = p->next) {
        // 防止漏判，RST、FIN已经做了放重复处理，这里再判一次
        if (p->a_tcp == stream) {
            free(new_timeout_tcp);
            return;
        }
        if (p->sec > new_timeout_tcp->sec) {
            break;
        }
        new_timeout_tcp->pre = p;
    }
    if (new_timeout_tcp->pre == NULL) {
        tcp_timeouts = new_timeout_tcp;
    } else {
        new_timeout_tcp->pre->next = new_timeout_tcp;
    }
    if (new_timeout_tcp->next) {
        new_timeout_tcp->next->pre = new_timeout_tcp;
    }
}

static void del_closing_timeout_tcp_stream(TCP_Stream* stream) {
    TCP_Stream_Timeout* p = NULL;
    for (p = tcp_timeouts; p; p = p->next) {
        if (p->a_tcp == stream) {
            break;
        }
    }
    if (p == NULL) {  // 空表
        return;
    }
    if (p->pre == NULL) {  // 表头
        tcp_timeouts = p->next;
    } else {
        p->pre->next = p->next;
    }
    if (p->next) {
        p->next->pre = p->pre;
    }
    free(p);
}

static void free_tcp_queue_data(TCP_Half_Stream* half) {
    Socket_Buffer* p = half->list;
    while (p) {
        free(p->data);
        Socket_Buffer* tmp = p->next;
        free(p);
        p = tmp;
    }
    half->list = half->listtail = NULL;
    half->rmem_alloc = 0;
    // 本身的data也需要free
    if (half->data) {
        free(half->data);
    }
}

// 声明一次，方便下面的函数使用
static void notify(TCP_Stream*, TCP_Half_Stream*, char);

static void free_a_timeout_tcp_stream(TCP_Stream* stream) {
    int hash_index = stream->hash_index;
    del_closing_timeout_tcp_stream(stream);
    free_tcp_queue_data(&stream->client);
    free_tcp_queue_data(&stream->server);
    // 从hash table中也要删除
    if (stream->next_node) {
        stream->next_node->pre_node = stream->pre_node;
    }
    if (stream->pre_node) {
        stream->pre_node->next_node = stream->next_node;
    } else {  // 在一条hash table元素的链表头部
        hash_table[hash_index] = stream->next_node;
    }
    // 通知回调函数释放资源
    notify(stream, &stream->client, 1);
    notify(stream, &stream->server, 1);
    memset(stream, 0, sizeof(TCP_Stream));
    stream->next_free = free_streams;  // 多线程处理PV操作
    if (stream == tcp_oldest) {
        tcp_oldest = stream->pre_time;
    }
    if (stream = tcp_latest) {
        tcp_latest = stream->next_time;
    }
    free_streams = stream;
    tcp_num--;
}

/**
 * @brief 此函数在捕到包时调用，将超时链表中发生超时的流清理掉
 *
 * @param now 当前的时间戳
 */
void free_timeout_tcp_streams(time_t* now) {
    TCP_Stream_Timeout* next;
    for (TCP_Stream_Timeout* p = tcp_timeouts; p; p = next) {
        if (*now < p->sec) {  // 逆序存放的链表，只要超时值还未到now，就不超时
            return;
        }
        next = p->next;
        free_a_timeout_tcp_stream(p->a_tcp);
    }
}

// 将新的tcp_stream插入到hash table 的表头,更新两个半连接的状态信息
static TCP_Stream* add_new_tcp(struct tcphdr* tcpheader,
                               struct iphdr* ipheader,
                               int normal) {
    // 监听的流达到上限，将timeout链表表头的设为超时，删除流
    if (tcp_num > tcp_stream_pool_size) {  // 超限
        free_a_timeout_tcp_stream(tcp_oldest);
    }
    TCP_Stream* stream = free_streams;
    if (stream == NULL) {
        show_log(__func__, "There is no free stream space!\n");
        abort();  //出现重大问题，系统直接停止
    }
    tcp_num++;
    free_streams = free_streams->next_free;
    // 填充新stream
    memset(stream, 0, sizeof(TCP_Stream));
    Tuple tuple;
    int hash_index = 0;
    if (normal) {                                     // 监听完整的流
        if (tcpheader->syn && tcpheader->ack == 0) {  // SYN
            generate_tuple(&tuple, ipheader, tcpheader, 1);
            stream->client.state = TCP_SYN_SENT;
            stream->client.seqNum = ntohl(tcpheader->seq);
            stream->client.first_data_seq = stream->client.seqNum + 1;
            stream->server.state = TCP_CLOSE;
            hash_index = mk_hash_index(&tuple);
            stream->hash_index = hash_index;
            stream->tuple = tuple;
        }
    } else {
        if (tcpheader->syn && tcpheader->ack) {  // SYN+ACK
            generate_tuple(&tuple, ipheader, tcpheader, 0);
            stream->client.state = TCP_SYN_SENT;
            stream->client.seqNum = ntohl(tcpheader->ack_seq) - 1;
            stream->client.first_data_seq = stream->client.seqNum + 1;
            stream->server.ackNum = ntohl(tcpheader->ack_seq);
            stream->server.seqNum = ntohl(tcpheader->seq);
            stream->server.first_data_seq = stream->server.seqNum + 1;
            stream->server.state = TCP_SYN_RECV;
            hash_index = mk_hash_index(&tuple);
            stream->hash_index = hash_index;
            stream->tuple = tuple;
        } else {  //不完整的流
                  //根据端口号判定上下行建流
            int fromclient =
                ntohs(tcpheader->source) < ntohs(tcpheader->dest) ? 0 : 1;
            generate_tuple(&tuple, ipheader, tcpheader, fromclient);
            stream->tuple = tuple;
            stream->server.state = stream->client.state = TCP_ESTABLISHED;
            if (fromclient) {
                stream->client.ackNum = ntohl(tcpheader->ack_seq);
                stream->client.seqNum = ntohl(tcpheader->seq);
                stream->client.first_data_seq = stream->client.seqNum;
            } else {
                stream->server.ackNum = ntohl(tcpheader->ack_seq);
                stream->server.seqNum = ntohl(tcpheader->seq);
                stream->server.first_data_seq = stream->server.seqNum;
            }
            hash_index = mk_hash_index(&tuple);
            stream->hash_index = hash_index;
        }
    }
    stream->normal = normal;
    // 将流插入到hash table中，头插法，采用拉链法避免哈希冲突
    // 同时维护它的前驱和后继结点，防止删流导致内存泄漏
    TCP_Stream* tmp = hash_table[hash_index];
    stream->next_node = tmp;
    if (tmp) {
        tmp->pre_node = stream;
    }
    stream->pre_node = NULL;
    hash_table[hash_index] = stream;
    stream->next_time = tcp_latest;
    stream->pre_time = NULL;
    if (tcp_oldest == NULL) {
        tcp_oldest = stream;
    }
    if (tcp_latest) {
        tcp_latest->pre_time = stream;
    }
    tcp_latest = stream;
#ifdef _DEBUG
    printf("one tcp strem created! sport:%d,dport:%d\n", tuple.src_port,
           tuple.dst_port);
#endif
    return stream;
}

static TCP_Stream* find_tcp_stream(Tuple* tuple) {
    int hash_index = mk_hash_index(tuple);
    TCP_Stream* a_tcp = NULL;
    // 链表满的情况下出现死循环？
    for (a_tcp = hash_table[hash_index];
         a_tcp && memcmp(&a_tcp->tuple, tuple, sizeof(Tuple));
         a_tcp = a_tcp->next_node)
        ;
    return a_tcp ? a_tcp : NULL;
}

static TCP_Stream* find_stream(struct tcphdr* tcpheader,
                               struct iphdr* ipheader,
                               int* from_client) {
    Tuple tuple;
    //提取四元组
    generate_tuple(&tuple, ipheader, tcpheader, 1);
    // 默认以端口号识别上下行
    TCP_Stream* stream = NULL;
    if (stream = find_tcp_stream(&tuple)) {
        *from_client = 1;
        return stream;
    }
    //交换src和dst再次检查
    generate_tuple(&tuple, ipheader, tcpheader, 0);

    if (stream = find_tcp_stream(&tuple)) {
        *from_client = 0;
        return stream;
    }
    return NULL;
}

static void add2buff(TCP_Half_Stream* rcv,
                     const unsigned char* data,
                     int datalen) {
    int toalloc;
    // 要加入的数据长度与缓冲区中已存在的数据长度之和大于缓冲区大小，扩充缓冲区
    if (datalen + rcv->ordered_count - rcv->offset > rcv->buffsize) {
        if (rcv->data == NULL) {  //设定初始的buffersize
            if (datalen < 2048) {
                toalloc = 4096;
            } else {
                toalloc = datalen * 2;
            }
            rcv->data = (unsigned char*)malloc(toalloc);
            rcv->buffsize = toalloc;
        } else {  //扩充缓冲区
            if (datalen < rcv->buffsize) {
                toalloc = 2 * rcv->buffsize;
            } else {
                toalloc = rcv->buffsize + 2 * datalen;
            }
            rcv->data = (unsigned char*)realloc(rcv->data, toalloc);
            rcv->buffsize = toalloc;
        }
        // 扩充失败
        if (rcv->data == NULL) {
            show_log(__func__, "no memory!");
            abort();
        }
    }
    memcpy(rcv->data + rcv->ordered_count - rcv->offset, data, datalen);
    rcv->ordered_count += datalen;
    rcv->new_count = datalen;
    rcv->count += rcv->new_count;
}

static void notify(TCP_Stream* stream, TCP_Half_Stream* rcv, char whatto) {
#ifdef _DEBUG
    printf("callback:stream:sport:%d,dport:%d\n", stream->tuple.src_port,
           stream->tuple.dst_port);
#endif
    // 1 得到上下行
    bool fromclient = ((rcv == &stream->client) ? true : false);
    for (Proc_node* node = pnode; node; node = node->next) {
        // 类型值的强制转换可能出现问题
        int ret = (int)((node->fun)(stream, fromclient, whatto));
        switch (ret) {
            case -2:  //不是属于该回调函数处理的数据
                break;
            case -1:  //删除
                rcv->ordered_count = 0;
                rcv->offset = 0;
                break;
            case 0:  //转发
                break;
            default:  //回调函数处理的字节数
                // 先转发，再移动数据
                rcv->offset = rcv->ordered_count - ret;
                if (rcv->offset < 0) {
                    // 应用层返回值有错
                    abort();
                }
                rcv->ordered_count = rcv->offset;
                memmove(rcv->data, rcv->data + ret, rcv->offset);
        }
    }
    // 没有回调函数处理，转发
    // put forward 不需要free?
}

static void add_data_from_socket_buffer(TCP_Stream* stream,
                                        TCP_Half_Stream* snd,
                                        TCP_Half_Stream* rcv,
                                        const unsigned char* data,
                                        uint32_t datalen,
                                        uint32_t tcp_seq) {
    // urg 数据不需要管
    uint32_t lost = EXPSEQ - tcp_seq;  // 需要释放的字节数
    if (datalen > lost) {              //可使滑动窗口后移
        // 将数据追加到halfstream->data
        add2buff(rcv, data + lost, datalen - lost);
        // 通知listener处理
        notify(stream, rcv, 0);
    }
    /*********************************************/
    // if(tcpheader->fin) ?
    // fin包统一处理？
    /*********************************************/
}

static void copy2current_headers(unsigned char* dst,
                                 struct tcphdr* tcpheader,
                                 struct iphdr* ipheader) {
    memcpy(dst, ipheader, ipheader->ihl * 4);
    memcpy(dst + ipheader->ihl * 4, tcpheader, tcpheader->doff * 4);
}

// 核心函数，TCP乱序重组+寻找listener
static void tcp_queque(TCP_Stream* stream,
                       struct tcphdr* tcpheader,
                       struct iphdr* ipheader,
                       TCP_Half_Stream* snd,
                       TCP_Half_Stream* rcv,
                       const unsigned char* data,
                       int datalen) {
    // 兼顾了序列号交叉的情况
    uint32_t tcp_seq = ntohl(tcpheader->seq);
#ifdef _DEBUG
    printf("EXPSEQ:%u\n", snd->first_data_seq + rcv->count);
#endif
    if (!after(tcp_seq, EXPSEQ)) {  // 序列号<=希望收到的序列号
        // 只有小于等于希望收到的序列号，才能使滑动窗口后移，才能向应用层交付有序数据
        // seq+datalen<EXPSEQ说明是个彻彻底底的旧包,需要释放，否则会使EXPSEQ后移
        if (after(tcp_seq + datalen + tcpheader->fin, EXPSEQ)) {  //交叉情况
            copy2current_headers(rcv->current_headers, tcpheader, ipheader);
            rcv->current_headers_len = tcpheader->doff * 4 + ipheader->ihl * 4;
            add_data_from_socket_buffer(stream, snd, rcv,
                                        data + rcv->current_headers_len,
                                        datalen, tcp_seq);

            //移动EXPSEQ后，检查list链表上是否满足了连续有序性
            Socket_Buffer* packet = rcv->list;
            while (packet) {
                if (after(packet->seq, EXPSEQ)) {
                    break;
                }

                // list中的乱序报文满足有序性&&存在序列号交叉的情况
                if (after(packet->seq + packet->len + packet->fin, EXPSEQ)) {
                    //头直接覆盖，数据追加
                    memcpy(rcv->current_headers, packet->headers,
                           packet->headers_len);
                    rcv->current_headers_len = packet->headers_len;
                    add_data_from_socket_buffer(
                        stream, snd, rcv,
                        packet->data + rcv->current_headers_len, packet->len,
                        packet->seq);
                }
                rcv->rmem_alloc -= packet->truesize;
                // 释放packet空间
                // 依次转换pre和next，因为不知道二者是否存在
                if (packet->pre) {
                    packet->pre->next = packet->next;
                } else {
                    rcv->list = packet->next;
                }
                if (packet->next) {
                    packet->next->pre = packet->pre;
                } else {
                    rcv->listtail = packet->pre;
                }
                Socket_Buffer* tmp = packet->next;
                free(packet->data);
                free(packet);
                packet = tmp;
            }
        } else {  // 是个彻底的旧包
            // free?
            return;
        }
    } else {  // 在EXPSEQ之后的数据包，照常收就好了，可设定接收上限实现滑动窗口
        Socket_Buffer* packet = (Socket_Buffer*)malloc(sizeof(Socket_Buffer));
        if (packet == NULL) {
            show_log(__func__, "allocate packet  memory failed!,no memory");
            abort();
        }
        // 暂时将truesize设置为结构体大小加data长度
        packet->data = (unsigned char*)malloc(datalen);
        if (packet->data == NULL) {
            show_log(__func__, "allocate data memory failed!,no memory");
            abort();
        }
        packet->truesize = sizeof(Socket_Buffer) + datalen;
        packet->len = datalen;
        rcv->rmem_alloc += packet->truesize;
        memcpy(packet->data, data, datalen);
        // fin、rst包丢失，设定10秒定时器删流的情况
        packet->fin = tcpheader->fin;
        packet->rst = tcpheader->rst;
        // if (packet->fin || packet->rst) {  // 设定定时器10秒，超时删流
        //     // to do
        //     // add stream to timeout list
        // }
        packet->seq = tcp_seq;
        copy2current_headers(packet->headers, tcpheader, ipheader);
        packet->headers_len = tcpheader->doff * 4 + ipheader->ihl * 4;
        Socket_Buffer* p = rcv->listtail;
        // 有序插入，从后往前找
        while (1) {
            if (!p || !after(p->seq, tcp_seq)) {
                break;
            }
            p = p->pre;
        }
        // rcv list为空，packet放在表头
        if (p == NULL) {
            packet->pre = NULL;
            packet->next = rcv->list;
            if (rcv->list) {
                rcv->list->pre = packet;
            }
            rcv->list = packet;
            if (!rcv->listtail) {
                rcv->listtail = packet;
            }
        } else {  //将packet放在p后面
            packet->next = p->next;
            p->next = packet;
            packet->pre = p;
            if (packet->next) {
                packet->next->pre = packet;
            } else {
                rcv->listtail = packet;
            }
        }
    }
}

// 核心函数，处理TCP报文的函数
void process_tcp(const unsigned char* data) {  // skblen?
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
    // tcp payload长度不能为负数
    int datalen =
        ntohs(ipheader->tot_len) - 4 * ipheader->ihl - 4 * tcpheader->doff;
    if (datalen < 0) {
        show_log(__func__, "tcp payload length error!");
        // free
        return;
    }
    //数据包的校验和
    if (my_tcp_check(tcpheader, ip_packet_len - 4 * ipheader->ihl,
                     ipheader->saddr, ipheader->daddr)) {
        show_log(__func__, "tcp check sum error!");
        // free
        return;
    }

    //-----端口匹配------
    // to do 读取前缀树规则（匹配IP、端口号）

    //三次握手、四次挥手、数据包交付
    // 不需要设计处理状态，只需要每个半连接的状态
    int from_client = 0;
    TCP_Stream* stream = find_stream(tcpheader, ipheader, &from_client);
    TCP_Half_Stream* receiver = NULL;
    TCP_Half_Stream* sender = NULL;
    if (stream) {  // 前提是hash表中已经存在流
        if (from_client) {
            sender = &stream->client;
            receiver = &stream->server;
        } else {
            sender = &stream->server;
            receiver = &stream->client;
        }
    }
    // SYN？
    if (tcpheader->syn && tcpheader->ack == 0 && tcpheader->rst == 0) {
        if (!stream) {  //监听完整的TCP流，更新半连接的状态，normal标志位值为一
            stream = add_new_tcp(tcpheader, ipheader, 1);
        } else {  // 转发
            if (receiver->state == TCP_SYN_RECV) {
                // free,抵御DOS攻击;
                return;
            }
        }
        // 转发 put forward to
        return;
    }
    // SYN+ACK?
    if (tcpheader->syn && tcpheader->ack && tcpheader->rst == 0) {
        // find stream
        // ，在流中判定半连接的状态是否为SYN_SENT和CLOSED，是则置normal标志位值为一
        // 不在流中更新半连接的状态
        if (!stream) {  // hash表中没有，需要建表
            stream = add_new_tcp(tcpheader, ipheader, 0);
        } else {  // 正常的的数据流，检查半连接的标志位,更新标志位,序列号，ACK值
            if (stream->server.state == TCP_CLOSE &&
                stream->client.state == TCP_SYN_SENT &&
                stream->client.seqNum + 1 == ntohl(tcpheader->ack_seq)) {
                stream->server.state = TCP_SYN_RECV;
                stream->server.ackNum = ntohl(tcpheader->ack_seq);
                stream->server.seqNum = ntohl(tcpheader->seq);
                stream->server.first_data_seq = stream->server.seqNum + 1;
            }
            //无条件转发数据,SYN_ACK超时和冗余双发的协议栈都有处理机制
        }
        // put forward to
        return;
    }

    // ACK?
    if (tcpheader->ack) {  // 不返回!!!
        // stream=NULL==>normal=0==>add_new_tcp(按照normal标志位按照规则建立流)
        // 检查流的状态，更新流状态
        // 绑定监听的回调函数
        if (!stream) {
            // 建流，在最后判断是否有数据字段
            stream = add_new_tcp(tcpheader, ipheader, 0);
            int fromclient =
                ntohl(tcpheader->source) < ntohl(tcpheader->dest) ? 0 : 1;
            if (fromclient) {
                sender = &stream->client;
                receiver = &stream->server;
            } else {
                sender = &stream->server;
                receiver = &stream->client;
            }
            if (datalen > 0) {
                // process data
                // 通知listeners处理数据+寻找新的listener

                tcp_queque(stream, tcpheader, ipheader, sender, receiver, data,
                           datalen);
            }
        } else {
            // handle_ack();
            // if (before(ntohl(tcpheader->seq) + datalen), receiver->ackNum) {
            //     // 旧包可放行
            //     // put forward to ip level
            // }
            // client发给server的三次握手包的确认包
            if (from_client && stream->server.state == TCP_SYN_RECV &&
                stream->client.state == TCP_SYN_SENT &&
                ntohl(tcpheader->ack_seq) == stream->server.seqNum + 1) {
                stream->client.state = TCP_ESTABLISHED;
                stream->client.seqNum = ntohl(tcpheader->seq);
                stream->client.ackNum = ntohl(tcpheader->ack_seq);
#ifdef _DEBUG
                printf("one stream established,sport:%d,dstport:%d\n",
                       stream->tuple.src_port, stream->tuple.dst_port);
#endif
            } else if (!from_client &&
                       stream->client.state == TCP_ESTABLISHED &&
                       stream->server.state == TCP_SYN_RECV) {
                // 没有SYN的情况下可能出现累积确认的情况
                stream->server.state = TCP_ESTABLISHED;
                stream->server.seqNum = ntohl(tcpheader->seq);
                stream->server.ackNum = ntohl(tcpheader->ack_seq);
            }
            if (sender->state == TCP_ESTABLISHED) {
                if (sender->first_data_seq == 0) {  // 不完整流first seq的问题
                    sender->first_data_seq = ntohl(tcpheader->seq);
                }
                // 正常的数据包，交给data处理部分
                if (datalen > 0) {
                    // process data
                    // 通知listeners处理数据+寻找新的listener
                    tcp_queque(stream, tcpheader, ipheader, sender, receiver,
                               data, datalen);
                }
            }
        }
    }
    if (datalen = 0) {
        // 转发
    }
    if (tcpheader->rst) {
        if (stream == NULL) {
            // free
            return;
        } else {
            // 加入超时链表
        }
        return;
    }
    if (tcpheader->fin) {
        // stream=NULL=>直接return
        // 更新两个半连接的状态，normal=0的流也可正常处理，删流靠超时时间
        if (stream == NULL) {  //新流只捕到FIN包
            return;
        }
        if (sender->state == TCP_ESTABLISHED &&
            receiver->state == TCP_ESTABLISHED) {
            sender->state = TCP_CLOSING;
            //加入超时链表
        }
        return;
    }
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
    hash_table = (TCP_Stream**)calloc(size, sizeof(TCP_Stream*));
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
        tcp_stream_pool[i].next_free = &(tcp_stream_pool[i + 1]);
    }
    tcp_stream_pool[tcp_stream_pool_size].next_free = NULL;
    free_streams = tcp_stream_pool;
    init_hash();
    return 0;
}