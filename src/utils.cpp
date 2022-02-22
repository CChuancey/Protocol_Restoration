#include "utils.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "trie.h"

char last_modified_time[50];

int connect_to_sql(MYSQL** mysql) {
    *mysql = mysql_init(NULL);
    assert(*mysql != NULL);
    unsigned int timeout = 3000;
    mysql_options(*mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    if (mysql_real_connect(*mysql, DBHOST, DBUSER, DBPASSWD, DBNAME, DBPORT,
                           NULL, 0) == NULL) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n",
                mysql_error(*mysql));
        return -1;
    }
    return 0;
}

void release_sql_resource(MYSQL* sql) {
    mysql_close(sql);     //关闭与mysql服务器的连接
    mysql_library_end();  //关闭MySQL数据库的使用
}

int execute_sql_cmd(MYSQL* sql, const char* sql_str) {
    printf("execute sql string:%s\n", sql_str);
    if (mysql_real_query(sql, sql_str, strlen(sql_str)) != 0) {
        fprintf(stderr, "query failed: %s\n", mysql_error(sql));
        return -1;
    }
    return 0;
}

void update_trie(MYSQL* sql, Trie* root) {
    if (execute_sql_cmd(sql, "select * from `rules`") == -1) {
        fprintf(stderr, "sql cmd executed failed!\n");
        return;
    }
    MYSQL_RES* res = mysql_store_result(sql);
    if (res == NULL) {
        fprintf(stderr, "fetch result failed: %s\n", mysql_error(sql));
        return;
    }
    MYSQL_ROW row = NULL;
    char trie_str[SQL_STR_LEN];
    while ((row = mysql_fetch_row(res)) != NULL) {
        if (atoi(row[5])) {
            sprintf(trie_str, "sip:%s dip:%s sport:%s dport:%s", row[1], row[2],
                    row[3], row[4]);
            puts(trie_str);
            insert(root, trie_str, atoi(row[0]));
        }
    }
}

int init_worker_trie() {
    MYSQL* sql = NULL;
    if (connect_to_sql(&sql) == -1) {
        fprintf(stderr, "connected sql server failed\n");
        return -1;
    }
    worker_trie = mk_trie();
    update_trie(sql, worker_trie);
    puts("work trie was ready");
}

/**
 * @brief
 * 连接上数据库，并将数据库表的更新时间缓存到本地
 *
 * @return int
 */
int init_last_modified_time(MYSQL* sql) {
    if (connect_to_sql(&sql) == -1) {
        fprintf(stderr, "connected sql server failed\n");
        return -1;
    } else {
        fprintf(stderr, "connected sql server succeeded!\n");
    }
    if (execute_sql_cmd(
            sql,
            "SELECT ifnull(update_time,create_time) FROM "
            "information_schema.tables WHERE "
            "TABLE_SCHEMA = 'FlowCleaning' AND TABLE_NAME = 'rules';") == -1) {
        fprintf(stderr, "sql cmd executed failed!\n");
        return -1;
    } else {
        MYSQL_RES* res = mysql_store_result(sql);
        if (res == NULL) {
            fprintf(stderr, "fetch result failed: %s\n", mysql_error(sql));
            return -1;
        }
        MYSQL_ROW row = mysql_fetch_row(res);
        if (row == NULL) {
            fprintf(stderr, "fetch result is null\n");
            return -1;
        }
        sprintf(last_modified_time, "%s", row[0]);
        if (last_modified_time == NULL) {
            fprintf(stderr, "update last modified time failed\n");
            return -1;
        }
    }
    return 0;
}

/**
 * @brief
 * 交由单独的线程处理，检查数据库是否发生了改变；
 * 如果sql交互出错打印日志并退出线程，否则通知工作线程替换新的前缀树规则
 *
 */
void* check_sql_server_status(void* s) {
    MYSQL* sql = NULL;
    if (connect_to_sql(&sql) == -1) {
        return NULL;
    }
    if (init_last_modified_time(sql) == -1) {
        return NULL;
    }
    if (init_worker_trie() == -1 || worker_trie == NULL) {
        fprintf(stderr, "worker trie initialized failed\n");
        return NULL;
    }
    printf("%s is running\n", __func__);

    while (1) {
        sleep(1);  // 每隔三秒查询一次
        // puts("hello");
        int ret = execute_sql_cmd(
            sql,
            "SELECT update_time FROM "
            "information_schema.tables WHERE "
            "TABLE_SCHEMA = 'FlowCleaning' AND TABLE_NAME = 'rules';");
        if (ret == -1) {
            fprintf(stderr, "sql cmd executed failed!\n");
            pthread_exit(NULL);
        } else {
            MYSQL_RES* res = mysql_store_result(sql);
            if (res == NULL) {
                fprintf(stderr,
                        "fetch tmp update last modified result failed: %s\n",
                        mysql_error(sql));
                pthread_exit(NULL);
            }
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row == NULL) {
                fprintf(stderr,
                        "fetch tmp update last modified result is null\n");
                pthread_exit(NULL);
            }
            char tmp_modified_time[50];
            sprintf(tmp_modified_time, "%s", row[0]);
            if (tmp_modified_time == NULL) {
                fprintf(stderr, "get tmp update last modified time failed\n");
                pthread_exit(NULL);
            }
            // printf("last time:%s tmp time:%s\n", last_modified_time,
            //        tmp_modified_time);
            if (strcasecmp(tmp_modified_time, last_modified_time) == 0) {
                continue;
            } else {  // 发生了修改
                // 拉取数据区规则放入前缀树
                puts("detected rules changed");
                sprintf(last_modified_time, "%s", tmp_modified_time);
                new_trie = mk_trie();
                update_trie(sql, new_trie);
                pthread_mutex_lock(&trie_replace_mutex);
                worker_trie = new_trie;
                pthread_mutex_unlock(&trie_replace_mutex);
            }
        }
    }
    return NULL;
}
