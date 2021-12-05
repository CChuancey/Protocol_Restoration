#ifndef __UTILS_H__
#define __UTILS_H__

static inline int before(unsigned int seq1, unsigned int seq2) {
    return ((int)(seq1 - seq2) < 0);
}

static inline int after(unsigned int seq1, unsigned int seq2) {
    // 不能简单地写成!before，因为存在大于等于的情况
    return ((int)(seq1 - seq2) > 0);
}

#endif