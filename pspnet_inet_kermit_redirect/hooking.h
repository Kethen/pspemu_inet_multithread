#ifndef _HOOKING_
#define _HOOKING_
#include "log.h"

#include <psputils.h>
#include <pspsdk.h>
#include <psploadcore.h>

u32 MakeSyscallStub(void *function);

#define MAKE_JUMP(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a);

#define GET_JUMP_TARGET(x) (0x80000000 | (((x) & 0x03FFFFFF) << 2))

u32 offset_digital_to_analog = 0;
u32 offset_populate_car_digital_control = 0;
u32 offset_populate_car_analog_control = 0;

#define HIJACK_FUNCTION(a, f, ptr, u) \
{ \
	LOG("%s: hijacking function at 0x%lx with 0x%lx\n", __func__, (u32)a, (u32)f); \
	u32 _func_ = (u32)a; \
	u32 _ff = (u32)f; \
	if(u){ \
		_ff = MakeSyscallStub(f); \
	} \
	int _interrupts = pspSdkDisableInterrupts(); \
	sceKernelDcacheWritebackInvalidateAll(); \
	static u32 patch_buffer[3]; \
	_sw(_lw(_func_), (u32)patch_buffer); \
	_sw(_lw(_func_ + 4), (u32)patch_buffer + 8);\
	MAKE_JUMP((u32)patch_buffer + 4, _func_ + 8); \
	_sw(0x08000000 | (((u32)(_ff) >> 2) & 0x03FFFFFF), _func_); \
	_sw(0, _func_ + 4); \
	ptr = (void *)patch_buffer; \
	sceKernelDcacheWritebackInvalidateAll(); \
	sceKernelIcacheClearAll(); \
	pspSdkEnableInterrupts(_interrupts); \
	LOG("%s: original instructions: 0x%lx 0x%lx\n", __func__, _lw((u32)patch_buffer), _lw((u32)patch_buffer + 8)); \
}

#endif
