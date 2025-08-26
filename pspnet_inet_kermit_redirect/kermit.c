#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include <pspsdk.h>
#include <psputils.h>
#include <pspthreadman.h>

#include "kermit.h"
#include "log.h"
#include "common.h"
#include "cache.h"

// references https://github.com/TheOfficialFloW/Adrenaline/blob/7d382b7837d9d211d830017ba7aee982fa49a8c6/cef/systemctrl/adrenaline.c#L55-L68

#define ALIGN(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

int sceKermitSendRequest661(SceKermitRequest *request, uint32_t mode, uint32_t cmd, uint32_t args, uint32_t is_callback, uint64_t *resp);

#define LOG_REQUESTS 0

#define NUM_REQUEST_SLOTS 16

struct gapped_request_slot {
	uint8_t cache_gap[0x40];
	struct request_slot slot;
};

// get around the message pipe architecture, at least going by https://github.com/DaveeFTW/vita_kermit/blob/90334991fcf2b93c42cdf767d60b825ccee9d1b1/kermit.c#L48-L165
struct {
	struct gapped_request_slot request_slots[NUM_REQUEST_SLOTS];
	uint8_t cache_gap[0x40];
	bool request_slot_in_use[NUM_REQUEST_SLOTS];
} _request_slots = {0};

struct gapped_request_slot *const request_slots = _request_slots.request_slots;
bool *const request_slot_in_use = _request_slots.request_slot_in_use;

SceUID request_slots_mutex = -1;

static int reserve_request_slot(){
	int k1 = pspSdkSetK1(0);
	while(true){
		sceKernelWaitSema(request_slots_mutex, 1, 0);
		for(int i = 0;i < NUM_REQUEST_SLOTS;i++){
			if (!request_slot_in_use[i]){
				request_slot_in_use[i] = true;
				sceKernelSignalSema(request_slots_mutex, 1);
				pspSdkSetK1(k1);
				return i;
			}
		}
		sceKernelSignalSema(request_slots_mutex, 1);
		sceKernelDelayThread(10000);
	}
}

static void free_request_slot(int index){
	int k1 = pspSdkSetK1(0);
	sceKernelWaitSema(request_slots_mutex, 1, 0);
	request_slot_in_use[index] = false;
	sceKernelSignalSema(request_slots_mutex, 1);
	pspSdkSetK1(k1);
}

uint64_t _kermit_send_request(uint32_t mode, uint32_t cmd, int num_args, int nbio, ...){
	int free_slot_index = reserve_request_slot();
	struct request_slot *slot = &request_slots[free_slot_index].slot;
	slot->done = false;
	slot->mode = mode;
	slot->cmd = cmd;
	slot->psp_thread = sceKernelGetThreadId();
	slot->nbio = nbio;

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
	do_cache(DCACHE_WRITEBACKINVALIDATE, slot, sizeof(slot[0]));

	lock_transmit_mutex();
	uint64_t response = 0;
	sceKermitSendRequest661(request_uncached, mode, cmd, 14, 0, &response);
	unlock_transmit_mutex();

	int orig_priority = sceKernelGetThreadCurrentPriority();
	sceKernelChangeThreadPriority(0, 111);

	uint32_t cycles = 0;
	while (!slot->done){
		do_cache(DCACHE_INVALIDATE, slot, sizeof(slot[0]));

		sceKernelDelayThread(nbio ? 50 : cycles < 100 ? 5000 : 200000);
		cycles++;
	}

	sceKernelChangeThreadPriority(0, orig_priority);

	lock_transmit_mutex();

	uint64_t ret = slot->ret;
	free_request_slot(free_slot_index);
	pspSdkSetK1(k1);

	return ret;
}
