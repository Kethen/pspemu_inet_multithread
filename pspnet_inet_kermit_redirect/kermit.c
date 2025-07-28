#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include <pspsdk.h>
#include <psputils.h>
#include <pspthreadman.h>

#include "kermit.h"

#include "log.h"

// references https://github.com/TheOfficialFloW/Adrenaline/blob/7d382b7837d9d211d830017ba7aee982fa49a8c6/cef/systemctrl/adrenaline.c#L55-L68

#define ALIGN(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

int sceKermitSendRequest661(SceKermitRequest *request, uint32_t mode, uint32_t cmd, uint32_t args, uint32_t is_callback, uint64_t *resp);

#define LOG_REQUESTS 0

// get around the message pipe architecture, at least going by https://github.com/DaveeFTW/vita_kermit/blob/90334991fcf2b93c42cdf767d60b825ccee9d1b1/kermit.c#L48-L165
struct request_slot request_slots[16];

static struct request_slot *reserve_request_slot(){
	while(true){
		int interrupts = pspSdkDisableInterrupts();
		for(int i = 0;i < sizeof(request_slots) / sizeof(request_slots[0]);i++){
			if (!request_slots[i].in_use){
				request_slots[i].in_use = true;
				request_slots[i].done = false;
				pspSdkEnableInterrupts(interrupts);
				return &request_slots[i];
			}
		}
		pspSdkEnableInterrupts(interrupts);
		sceKernelDelayThread(10000);
	}
}

static void free_request_slot(struct request_slot *slot){
	int interrupts = pspSdkDisableInterrupts();
	slot->in_use = false;
	pspSdkEnableInterrupts(interrupts);
}

uint64_t _kermit_send_request(uint32_t mode, uint32_t cmd, int num_args, int nbio, ...){
	struct request_slot *slot = reserve_request_slot();
	slot->mode = mode;
	slot->cmd = cmd;
	slot->psp_thread = sceKernelGetThreadId();

	#if LOG_REQUESTS
	char args_log[255];
	int args_log_offset = 0;
	#endif

	va_list args;
	va_start(args, nbio);
	for (int i = 0;i < num_args;i++){
		slot->args[i] = va_arg(args, uint64_t);
		#if LOG_REQUESTS
		args_log_offset += sprintf(&args_log[args_log_offset], "0x%x ", *(uint32_t*)&request_aligned->args[i]);
		#endif
	}
	va_end(args);

	memset(slot->buf, 0, sizeof(slot->buf));
	SceKermitRequest *request_aligned = (SceKermitRequest *)ALIGN((u32)slot->buf, 0x40);
	SceKermitRequest *request_uncached = (SceKermitRequest *)((u32)request_aligned | 0x20000000);

	request_aligned->cmd = cmd;

	request_aligned->args[0] = (uint32_t)slot;
	#if 0
	for (int i = 1;i < 14;i++){
		request_aligned->args[i] = (uint32_t)i;
	}
	#endif

	#if LOG_REQUESTS
	LOG("%s: requesting mode 0x%x cmd 0x%d %s\n", __func__, mode, cmd, args_log);
	#endif

	int k1 = pspSdkSetK1(0);
	sceKernelDcacheWritebackInvalidateRange(slot, sizeof(struct request_slot));

	asm volatile ("" : : : "memory");

	uint64_t response = 0;
	sceKermitSendRequest661(request_uncached, mode, cmd, 14, 0, &response);
	sceKernelDelayThread(500);
	sceKernelDcacheWritebackInvalidateRange(&slot->done, sizeof(slot->done));
	sceKernelDcacheWritebackInvalidateRange(&slot->ret, sizeof(slot->ret));
	uint32_t cycles = 0;
	while (!slot->done){
		sceKernelDelayThread(nbio ? 500 : cycles < 100 ? 5000 : 200000);
		sceKernelDcacheWritebackInvalidateRange(&slot->done, sizeof(slot->done));
		sceKernelDcacheWritebackInvalidateRange(&slot->ret, sizeof(slot->ret));
		cycles++;
	}

	pspSdkSetK1(k1);

	uint64_t ret = slot->ret;

	asm volatile ("" : : : "memory");

	free_request_slot(slot);
	return ret;
}
