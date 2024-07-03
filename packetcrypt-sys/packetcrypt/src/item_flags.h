#ifndef ITEM_FLAGS_H
#define ITEM_FLAGS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define ITEM_FLAG_UNSET 0
#define ITEM_FLAG_SET 1

typedef struct {
  uint8_t *buffer;
  uint32_t count; // number of allocations
} Item_Flags_t;

inline uint8_t item_flags_read(Item_Flags_t *flags, uint32_t position) {
  return (flags->buffer[position >> 3]) >> (8 - (position % 8)) & 1;
}


inline void item_flags_set(Item_Flags_t *flags, uint32_t position,
                            uint8_t value) {
  flags->buffer[position >> 3] |= ((value & 1) << (8 - (position % 8)));
}

inline uint32_t item_flags_set_count(Item_Flags_t *flags) {
  uint32_t count = 0;
  for (uint32_t pos = 0; pos < flags->count; pos++) {
    if (item_flags_read(flags, pos) == 1) {
      count++;
    }
  }
  return count;
}

inline Item_Flags_t *item_flags_make(uint32_t count) {
  Item_Flags_t *flags = (Item_Flags_t *)malloc(sizeof(Item_Flags_t));

  uint32_t size = (uint32_t)ceil(count / (float)8);
  flags->buffer = (uint8_t *)malloc(size);
  flags->count = count;

  memset(flags->buffer, 0, size);

  return flags;
}

inline void item_flags_reset(Item_Flags_t *flags) {
   uint32_t size = (uint32_t)ceil(flags->count / (float)8);
  memset(flags->buffer, 0, size);
}

inline void item_flags_free(Item_Flags_t *flags) {
  if (flags == NULL)
    return;
  if (flags->buffer != NULL && flags->count > 0) {
    free(flags->buffer);
    flags->buffer = NULL;
  }
  free(flags);
  flags = NULL;
}

#endif