#ifndef __KERMIT_H
#define __KERMIT_H

#include "../kermit_common.h"

extern int (*kermit_respond_request)(int type, SceKermitRequest *, uint64_t response);

typedef enum kermit_addr_mode{
	// psp -> vita
	KERMIT_ADDR_MODE_IN = 1,
	// vita -> psp
	KERMIT_ADDR_MODE_OUT = 2,
	KERMIT_ADDR_MODE_INOUT = 3
} kermit_addr_mode;

extern void *(*kermit_get_pspemu_addr_from_psp_addr)(uint32_t psp_addr, kermit_addr_mode mode, uint32_t size);
extern int (*kermit_pspemu_writeback_cache)(void *addr, int size);
#endif
