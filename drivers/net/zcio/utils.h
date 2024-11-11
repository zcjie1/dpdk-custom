#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdbool.h>

static inline void set_bit(uint64_t *value, int n) 
{
    if (n < 0 || n >= 64)
        return;
    *value |= (uint64_t)1 << n;
}

static inline void clear_bit(uint64_t *value, int n) 
{
    if (n < 0 || n >= 64)
        return;
    *value &= ~(uint64_t)1 << n;
}

static inline bool is_bit_set(uint64_t value, int n)
{
    if (n < 0 || n >= 64)
        return false;
    return (value & ((uint64_t)1 << n)) != 0;
}

static inline bool is_bit_clear(uint64_t value, int n)
{
    if (n < 0 || n >= 64)
        return false;
    return (value & ((uint64_t)1 << n)) == 0;
}

static void lock_mutex(atomic_flag *lock) {
    while (atomic_flag_test_and_set(lock));  // 自旋等待锁
}

static void unlock_mutex(atomic_flag *lock) {
    atomic_flag_clear(lock);  // 释放锁
}

#endif // !__UTILS_H__