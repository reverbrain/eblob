#ifndef __EBLOB_CRC32_H
#define __EBLOB_CRC32_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * crc32_buffer() - computes CRC32 of @buffer with @length by updating previously computed CRC32 @previousCrc32.
 * If there is no previously computed CRC32, @previousCrc32 should be set to 0.
 *
 * Returns calculated CRC32.
 */
uint32_t crc32_buffer(const void* buffer, size_t length, uint32_t previousCrc32 = 0);

#ifdef __cplusplus
}
#endif

#endif /* __EBLOB_CRC32_H */