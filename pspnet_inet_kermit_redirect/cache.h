#ifndef __CACHE_H
#define __CACHE_H

#include <stdint.h>

typedef enum {
	DCACHE_WRITEBACK = 1,
	DCACHE_INVALIDATE = 2,
	DCACHE_WRITEBACKINVALIDATE = 3,
} cache_op;

void do_cache(cache_op op, void *location, uint32_t size);

#endif
