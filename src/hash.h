#ifndef __HASH_H__
#define __HASH_H__
#include <sys/time.h>
#include <sys/types.h>

typedef __u_char u_char;
typedef __u_int u_int;
typedef __u_short u_short;

void init_hash();
u_int mkhash(u_int, u_short, u_int, u_short);
#endif