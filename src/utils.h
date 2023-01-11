#ifndef __UTILS_H__
#define __UTILS_H__
#include <stdint.h>

static inline int before(uint32_t seq1, uint32_t seq2) {
  return ((int)(seq1 - seq2) < 0);
}

static inline int after(uint32_t seq1, uint32_t seq2) {
  // 不能简单地写成!before，因为存在大于等于的情况
  return ((int)(seq1 - seq2) > 0);
}

#endif