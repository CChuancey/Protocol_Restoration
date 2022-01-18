#include "trie.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

Trie* worker_trie = NULL;
Trie* new_trie = NULL;

pthread_mutex_t trie_replace_mutex;
pthread_mutex_t trie_thread_num_mutex;
int using_trie_thread_num = 0;

static Trie* trie_pool = NULL;
static Trie* trie_pool_back = NULL;

/**
 * @brief 申请一个trie空间挂到pool中统一释放
 *
 * @return Trie*
 */
Trie* mk_trie() {
    Trie* nnode = (Trie*)malloc(sizeof(Trie));
    memset(nnode, 0, sizeof(Trie));
    if (trie_pool == NULL) {
        trie_pool = nnode;
        trie_pool_back = nnode;
    } else {
        trie_pool_back->next_free = nnode;
        trie_pool_back = nnode;
    }
}

bool insert(Trie* root, const char* str, int id) {
    int len = strlen(str);
    if (len == 0 || root == NULL)
        return false;
    for (int i = 0; i < len; i++) {
        if (str[i] - '\0' < 0 || str[i] - '\0' > 127) {
            fprintf(stderr, "规则非法\n");
            return false;
        }
        if (root->next[str[i] - '\0'] == NULL) {
            Trie* nnode = mk_trie();
            root->next[str[i] - '\0'] = nnode;
            nnode->val = str[i];
        }
        root = root->next[str[i] - '\0'];
    }
    root->rule_id = id;
    return true;
}

int search(Trie* root, const char* str) {
    int len = strlen(str);
    if (len == 0 || root == NULL)
        return -1;
    for (int i = 0; i < len; i++) {
        if (str[i] - '\0' < 0 || str[i] - '\0' > 127) {
            fprintf(stderr, "search rules invalid!\n");
            return -1;
        }
        if (root->next[str[i] - '\0'] == NULL) {
            return -1;
        }
        root = root->next[str[i] - '\0'];
    }
    return root->rule_id;
}

void release_trie_resource() {
    while (trie_pool) {
        Trie* tmp = trie_pool->next_free;
        free(trie_pool);
        trie_pool = tmp;
    }
    trie_pool_back = NULL;
}
