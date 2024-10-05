#include "utils.h"

void set_bit(uint64_t *value, int n) 
{
    if (n < 0 || n >= 64)
        return;
    *value |= (uint64_t)1 << n;
}

void clear_bit(uint64_t *value, int n) 
{
    if (n < 0 || n >= 64)
        return;
    *value &= ~(uint64_t)1 << n;
}

bool is_bit_set(uint64_t value, int n)
{
    if (n < 0 || n >= 64)
        return false;
    return (value & ((uint64_t)1 << n)) != 0;
}

bool is_bit_clear(uint64_t value, int n)
{
    if (n < 0 || n >= 64)
        return false;
    return (value & ((uint64_t)1 << n)) == 0;
}