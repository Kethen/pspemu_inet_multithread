#ifndef __KERMIT_H
#define __KERMIT_H

// based on https://github.com/TheOfficialFlow/Adrenaline/blob/master/adrenaline_compat.h
// https://github.com/TheOfficialFloW/Adrenaline/blob/master/user/main.c
typedef struct {
	uint32_t cmd; //0x0
	SceUID sema_id; //0x4
	uint64_t *response; //0x8
	uint32_t padding; //0xC
	uint64_t args[14]; // 0x10
} SceKermitRequest; //0x80

extern int (*kermit_respond_request)(int type, SceKermitRequest *, uint64_t response);

typedef enum kermit_addr_mode{
	KERMIT_ADDR_MODE_IN = 1,
	KERMIT_ADDR_MODE_OUT = 2,
	KERMIT_ADDR_MODE_INOUT = 3
} kermit_addr_mode;

extern void *(*kermit_get_pspemu_addr_from_psp_addr)(uint32_t psp_addr, kermit_addr_mode mode, uint32_t size);

#endif
