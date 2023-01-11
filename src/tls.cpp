#include "tls.h"
#include "packet_local.h"
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/ssl3.h>
#include <openssl/x509.h>

/**
 * @brief 判定传来的数据包是不是TLS协议的报文
 *
 * @param data 数据
 * @param len 传入的必须满足len>5，TLS记录层头部长度为5字节
 * @param tuple
 * 传入四元组，主要是传入端口号，据统计在互联网中443端口的TLS流量高达90%
 * @return true
 * @return false
 */
static bool check_if_it_is_TLS_handshake(unsigned char* data,
                                         uint32_t len,
                                         Tuple* tuple) {
    // to do
    if (tuple->dst_port != 443 && tuple->src_port != 443)
        return false;
    const unsigned char tls1[5] = {0x16, 0x03, 0x03},
                        tls2[5] = {0x16, 0x03, 0x01};
    if (memcmp(data, tls1, 3) == 0 || memcmp(data, tls2, 3) == 0) {
        return true;
    }
    return false;
}

/**
 * @brief Get the server extension name object
 *
 * @param data
 * @param datalen
 * @return char* NULL或者实际的域名
 */
static char* get_server_extension_name(const char* data, uint32_t datalen) {
    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       next	Session ID Length
    */

    int pos = 38;
    /* session id */
    if (datalen < pos + 1)
        return NULL;
    uint16_t len = data[pos];
    pos += len + 1;

    /* Cipher Suites */
    if (datalen < pos + 2)
        return NULL;
    memcpy(&len, &data[pos], 2);
    len = ntohs(len);
    pos += len + 2;

    /* Compression Methods */ if (datalen < pos + 1)
        return NULL;
    len = data[pos];
    pos += len + 1;

    /* Extensions */
    if (datalen < pos + 2)
        return NULL;
    memcpy(&len, &data[pos], 2);
    len = ntohs(len);  // 此时len为Extensions的长度
    pos += 2;
    // parse extensions to get sni
    uint16_t extension_item_len;
    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= len) {
        memcpy(&extension_item_len, &data[pos + 2], 2);
        extension_item_len = ntohs(extension_item_len);
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {  // sni 字段
            if (pos + 4 + extension_item_len > len)
                return NULL;
            // get sni string
            pos += 6;
            uint16_t server_name_len;
            uint16_t extension_end = pos + extension_item_len - 2;
            while (pos + 3 < extension_end) {
                memcpy(&server_name_len, &data[pos + 1], 2);
                server_name_len = ntohs(server_name_len);
                if (pos + 3 + server_name_len > extension_end)
                    return NULL;
                char* hostname = (char*)malloc(server_name_len + 1);
                switch (data[pos]) {
                    case 0x00: /*host name*/
                        if (hostname == NULL) {
                            fprintf(stderr, "malloc hostname failed!\n");
                            return NULL;
                        }
                        strncpy(hostname, (char*)(data + pos + 3),
                                server_name_len);
                        hostname[server_name_len] = '\0';
                        return hostname;
                        break;
                    default:
                        puts("encouter error! debug me....");
                }
                pos += 3 + len;
            }
        }
        pos += 4 + extension_item_len;
    }
    return NULL;
}

/**
 * @brief Get the server extension name object
 *
 * @param data
 * @param datalen
 * @return char* NULL或者实际的域名
 */
static char *get_server_extension_name_by_openssl(const char *data,
                                                  uint32_t datalen) {
    PACKET packet{.curr = reinterpret_cast<const unsigned char *>(data),
                  .remaining = datalen};

    unsigned int handshake_type;
    uint64_t length;
    unsigned int version;
    uint8_t random[SSL3_RANDOM_SIZE];
    PACKET session_id_packet;
    PACKET cipher_suites;
    PACKET compressions;
    // 跳过前缀
    if (!PACKET_get_1(&packet, &handshake_type) ||
        handshake_type != CLIENT_HELLO) {
        return nullptr;
    }
    if (!PACKET_get_net_3(&packet, &length) || length != datalen - 4) {
        return nullptr;
    }
    if (!PACKET_get_net_2(&packet, &version) || version != TLS1_2_VERSION) {
        fprintf(stderr, "该握手报文TLS版本不是1.2");
        return nullptr;
    }
    if (!PACKET_copy_bytes(&packet, random, SSL3_RANDOM_SIZE) ||
        !PACKET_get_length_prefixed_1(&packet, &session_id_packet) ||
        !PACKET_get_length_prefixed_2(&packet, &cipher_suites) ||
        !PACKET_get_length_prefixed_1(&packet, &compressions)) {
        return nullptr;
    }

    // extensions is empty!
    if (PACKET_remaining(&packet) == 0) {
        return nullptr;
    }
    // 解析extensions
    PACKET extensions;
    if (!PACKET_get_length_prefixed_2(&packet, &extensions)) {
        return nullptr;
    }
    while (PACKET_remaining(&extensions) > 0) {
        PACKET extension;
        unsigned int type;
        if (!PACKET_get_net_2(&extensions, &type) ||
            !PACKET_get_length_prefixed_2(&extensions, &extension)) {
            return nullptr;
        }
        if (type != TLSEXT_TYPE_server_name) {
            continue;
        }
        // Found Server Name Extension
        PACKET sni;
        if (!PACKET_as_length_prefixed_2(&extension, &sni) ||
            PACKET_remaining(&sni) == 0) {
            return nullptr;
        }
        unsigned int servername_type;
        PACKET host_name;
        if (!PACKET_get_1(&sni, &servername_type) ||
            servername_type != TLSEXT_NAMETYPE_host_name ||
            !PACKET_as_length_prefixed_2(&sni, &host_name)) {
            return 0;
        }
        char *ret = nullptr;
        if (PACKET_remaining(&host_name) > TLSEXT_MAXLEN_host_name ||
            PACKET_contains_zero_byte(&host_name) ||
            !PACKET_strndup(&host_name, &ret)) {
            return nullptr;
        }
        return ret;
    }

    return nullptr;
}

/**
 * @brief 核心函数：解析得到数据包中的SNI，并查询SNI黑名单，决定是否将其过滤
 *
 * @param data
 * @param datalen
 * @return int
 * -2：不是TLS数据包
 * -1:需删流
 * >=0 :正常数据报文
 */
static int parse_sni(const char* data, uint32_t datalen) {
    // client hello数据报文的二次校验，保证程序的健壮性
    // char *sni = get_server_extension_name(data, datalen);
    char *sni = get_server_extension_name_by_openssl(data, datalen);
    if (sni == NULL)
        return datalen;
    puts(sni);
    // 读取规则进行匹配
    // 黑名单需加入ac自动机/trie

    free(sni);
    return datalen;
}

/**
 * @brief 创建一个证书链，方便后续新增需求，方便后续验证证书链
 *
 * @param data
 * @param datalen
 * @return int
 */
int create_stack(const unsigned char* data,
                 uint32_t datalen,
                 STACK_OF(X509) * sk) {
    uint32_t len;
    uint32_t pos = 0;
    while (pos + 3 < datalen) {
        ntoh(data + pos, &len);
        if (len == 0)
            return 1;

        const unsigned char* tmp = data + pos + 3;
        X509* cert = d2i_X509(NULL, &tmp, len);
        if (cert == NULL) {
            fprintf(stderr, "parse certificates failed!\n");
            return -1;
        }
        // // verify signature，只能实现对self signature的验证
        // EVP_PKEY* pkey = X509_get_pubkey(cert);
        // if (pkey == NULL) {
        //     fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        //     return 0;
        // }
        // int r = X509_verify(cert, pkey);
        // if (r <= 0) {
        //     fprintf(stderr, "certificate signature error!\n");
        //     return 0;
        // }
        // EVP_PKEY_free(pkey);
        sk_X509_push(sk, cert);
        pos += 3 + len;
    }
    return 1;
}

/**
 * @brief 从证书中加载位置信息到location中
 *
 * @param location
 * @return int
 */
int get_subject_location_string(STACK_OF(X509) * sk,
                                char* location[ENTRY_DEPTH]) {
    unsigned len = sk_X509_num(sk);
    if (len == 0) {  //空的证书链
        return -1;
    }
    // 提取subject的信息，进行过滤
    X509* cert = sk_X509_value(sk, 0);
    X509_NAME* subj = X509_get_subject_name(cert);
    for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
        X509_NAME_ENTRY* e = X509_NAME_get_entry(subj, i);
        ASN1_STRING* d = X509_NAME_ENTRY_get_data(e);
        int nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
        char* value = (char*)ASN1_STRING_data(d);
        location[nid - NID_commonName] = new char[strlen(value) + 1];
        // (char*)malloc(sizeof(char) * (strlen(value) + 1));

        strncpy(location[nid - NID_commonName], value, strlen(value));
        location[nid - NID_commonName][strlen(value)] = '\0';
        // puts(value);
    }
    return 0;
}

/**
 * @brief 检查证书的时间
 *
 * @param cert
 * @return true
 * @return false
 */
bool check_certificate_validity(X509* cert) {
    if (cert == NULL)
        return false;
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    int day, sec;
    if (!ASN1_TIME_diff(&day, &sec, NULL, not_before)) {
        fprintf(stderr, "asn1 time format error!\n");
        return false;
    }
    if (day >= 0 || sec >= 0) {
        return false;
    }
    if (!ASN1_TIME_diff(&day, &sec, NULL, not_after)) {
        fprintf(stderr, "asn1 time format error!\n");
        return false;
    }
    if (day <= 0 || sec <= 0) {
        return false;
    }
    return true;
}

/**
 * @brief
 * 核心函数：解析出Certificates中subject和issuers的信息，查询黑名单进行过滤
 *
 * @param data
 * @param datalen
 * @return int
 * -2：不是TLS数据包
 * -1:需删流
 * >=0 :正常数据报文
 */
static int parse_X509(const unsigned char* data, uint32_t datalen) {
    // 同理，二次验证certificate报文，保证程序的健壮性
    uint32_t len;
    ntoh(data + 4, &len);
    STACK_OF(X509)* sk = sk_X509_new_null();
    if (create_stack(data + 7, len, sk) == -1) {
        // 建栈失败，属于无法处理的报文，直接转发即可
        return datalen;
    }
    // 检验证书时间的有效性
    if (!check_certificate_validity(sk_X509_value(sk, 0))) {
        return datalen;
    }
    /**
     * @brief location:
     * 0:NID_commonName
     * 1:NID_countryName
     * 2:NID_localityName
     * 3:NID_stateOrProvinceName
     * 4:NID_organizationName
     * 5:NID_organizationalUnitName
     *
     */
    char* location[ENTRY_DEPTH] = {NULL};
    if (get_subject_location_string(sk, location) == -1)
        return datalen;
    // 加载规则进行过滤匹配

    for (int i = 0; i < ENTRY_DEPTH; i++) {
        if (location[i]) {
            delete[] location[i];
            location[i] = NULL;
        }
    }
    sk_X509_free(sk);
}

/**
 * @brief
 * 函数处理TLS数据包的函数入口 *
 * @param stream tcp流
 * @param fromclient 上下行
 * @param del   是否删流
 * @return int
 * -3: 删流成功
 * -2：不是TLS数据包
 * -1：需要将本次提交的数据包过滤
 *  0：需要将本次提交的数据转发
 * >0：本次提交数据包处理的字节数
 */
int process_tls(TCP_Stream* stream, bool fromclient, bool del) {
    // if (fromclient) {
    //     printf("message:\n%s\n", (char*)stream->client.data);
    // } else {
    //     printf("message:\n%s\n", (char*)stream->server.data);
    // }
    // return 0;
    if (del) {  // 不需要缓存流，数据存放在tcp,返回值无意义
        return -3;
    }
    unsigned char* data =
        fromclient ? stream->server.data : stream->client.data;
    uint32_t datalen = fromclient ? stream->server.ordered_count
                                  : stream->client.ordered_count;
    if (datalen <= 5)
        return 0;
    if (!check_if_it_is_TLS_handshake(data, datalen, &stream->tuple)) {
        return -2;
    }
    uint32_t handshake_packet_len = data[3] << 8;
    handshake_packet_len += data[4] + 5;
    // memcpy(&handshake_packet_len, data + 3, 2);
    // handshake_packet_len = ntohs(handshake_packet_len) + 5;
    // ntoh(data + 3, &handshake_packet_len);
    if (handshake_packet_len > datalen) {
        printf("waiting for more data\n");
        // 数据包长度不足以判定，等待数据包全部传输完整
        return 0;
    }
    puts("find a hand shake tls packet!");
    // 确定tls报文类型
    int ret = 0;
    printf("0x%x\n", data[5]);
    bool flag = false;
    switch (data[5]) {
        case CLIENT_HELLO:
            puts("收到client hello");
            flag = true;
            ret = parse_sni((const char*)(data + 5), datalen - 5);
            break;
        case CERTIFICATE:
            flag = true;
            puts("收到证书");
            ret = parse_X509(data + 5, handshake_packet_len - 5) + 5;
            break;
        default:
            puts("收到了其他TLS报文");
            // 报文之间粘连数据，需要剔除不需要的部分
            ret = handshake_packet_len;
            break;
    }
    if (flag)
        return datalen;
    return ret;
}