#include <psputils.h>
#include <pspsdk.h>

#include "cache.h"
#include "log.h"

void do_cache(cache_op op, void *location, uint32_t size){
	void (*cache_op_func)(const void *, unsigned int size) = NULL;
	if (op == DCACHE_WRITEBACK){
		cache_op_func = sceKernelDcacheWritebackRange;
	}else if (op == DCACHE_INVALIDATE){
		cache_op_func = sceKernelDcacheInvalidateRange;
	}else if (op == DCACHE_WRITEBACKINVALIDATE){
		cache_op_func = sceKernelDcacheWritebackInvalidateRange;
	}else{
		LOG("%s: bad cache op %d, please debug this\n", __func__, op);
		return;
	}

	// alignment, according to https://github.com/TheOfficialFloW/Adrenaline and https://github.com/mcidclan/me-dmacplus-me2sc , psp's caches are aligned to 0x40
	uint32_t aligned_location = (uint32_t)location;
	uint32_t aligned_size = size;
	uint32_t location_mod = aligned_location % 0x40;
	if (location_mod != 0){
		aligned_location = aligned_location - location_mod;
		aligned_size = size + location_mod;
	}

	uint32_t size_mod = aligned_size % 0x40;
	if (size_mod != 0){
		aligned_size = aligned_size + (0x40 - size_mod);
	}

	int k1 = pspSdkSetK1(0);
	cache_op_func((void *)aligned_location, aligned_size);
	pspSdkSetK1(k1);

	return;
}
