#ifndef __TRIE_H__
#define __TRIE_H__
#include <pthread.h>

#define MAX_CHILD 128

typedef struct Node {
    char val;
    struct Node* next[MAX_CHILD];
    struct Node* next_free;
    int rule_id;
} Trie;

extern Trie* worker_trie;
extern Trie* new_trie;
extern pthread_mutex_t trie_replace_mutex;
extern pthread_mutex_t trie_thread_num_mutex;
extern int using_trie_thread_num;

extern bool insert(Trie*, const char*, int id);
extern int search(Trie*, const char*);
extern void release_trie_resource();
extern Trie* mk_trie();

#endif