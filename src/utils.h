#ifndef __UTILS_H__
#define __UTILS_H__
#include <stdint.h>

#include <arpa/inet.h>
#include <assert.h>
#include <mysql/mysql.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#define DBHOST "127.0.0.1"
#define DBPORT 3306
#define DBUSER "root"
#define DBPASSWD "Zhangsan@elem123"
#define DBNAME "FlowCleaning"
#define SQL_STR_LEN 1024

extern char last_modified_time[50];

extern int connect_to_sql(MYSQL**);
extern void release_sql_resource(MYSQL*);
extern int init_last_modified_time(MYSQL*);
extern int execute_sql_cmd(MYSQL*, const char*);
extern void* check_sql_server_status(void*);

static inline int before(uint32_t seq1, uint32_t seq2) {
    return ((int)(seq1 - seq2) < 0);
}

static inline int after(uint32_t seq1, uint32_t seq2) {
    // 不能简单地写成!before，因为存在大于等于的情况
    return ((int)(seq1 - seq2) > 0);
}

#endif