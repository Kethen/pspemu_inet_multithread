#include <pspsysmem.h>
#include <pspmodulemgr.h>

#include "log.h"

int sceKernelQuerySystemCall(void *function);

u32 MakeSyscallStub(void *function) {
	SceUID block_id = sceKernelAllocPartitionMemory(PSP_MEMORY_PARTITION_USER, "", PSP_SMEM_High, 2 * sizeof(u32), NULL);
	u32 stub = (u32)sceKernelGetBlockHeadAddr(block_id);
	int syscall = sceKernelQuerySystemCall(function);
	LOG("%s: created stub block %d at 0x%x for function 0x%x syscall 0x%x\n", __func__, block_id, stub, function, syscall);
	_sw(0x03E00008, stub);
	_sw(0x0000000C | (syscall << 6), stub + 4);
	return stub;
}
