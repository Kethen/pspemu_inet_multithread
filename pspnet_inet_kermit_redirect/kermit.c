#include <stdarg.h>
#include <string.h>

#include <pspsdk.h>
#include <psputils.h>

#include "kermit.h"

// references https://github.com/TheOfficialFloW/Adrenaline/blob/7d382b7837d9d211d830017ba7aee982fa49a8c6/cef/systemctrl/adrenaline.c#L55-L68

#define ALIGN(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

int sceKermitSendRequest661(SceKermitRequest *request, uint32_t mode, uint32_t cmd, uint32_t args, uint32_t is_callback, uint64_t *resp);

uint64_t _kermit_send_request(uint32_t mode, uint32_t cmd, int num_args, ...){
	char buf[sizeof(SceKermitRequest) + 0x40];
	SceKermitRequest *request_aligned = (SceKermitRequest *)ALIGN((u32)buf, 0x40);
	SceKermitRequest *request_uncached = (SceKermitRequest *)((u32)request_aligned | 0x20000000);

	va_list args;
	va_start(args, num_args);
	for(int i = 0;i < num_args;i++){
		request_aligned->args[i] = va_arg(args, uint64_t);
	}
	va_end(args);

	request_aligned->cmd = cmd;

	int k1 = pspSdkSetK1(0);
	sceKernelDcacheInvalidateRange(request_aligned, sizeof(SceKermitRequest));

	uint64_t response = 0;
	sceKermitSendRequest661(request_uncached, mode, cmd, num_args, 0, &response);

	pspSdkSetK1(k1);

	return response;
}
