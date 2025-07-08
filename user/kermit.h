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

#endif
