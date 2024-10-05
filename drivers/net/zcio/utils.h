#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <stdbool.h>

void set_bit(uint64_t *value, int n);
void clear_bit(uint64_t *value, int n);
bool is_bit_set(uint64_t value, int n);
bool is_bit_clear(uint64_t value, int n);

#endif // !__UTILS_H__