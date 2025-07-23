#include <vitasdk.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/kernel/modulemgr.h>
#include <psp2common/kernel/iofilemgr.h>

#include <taihen.h>

#include "log.h"
#include "kermit.h"
#include "inet.h"

#define DUMP 1

static tai_hook_ref_t sceKernelCreateThreadRef = {0};
static tai_hook_ref_t kermit_wait_and_get_request_ref = {0};

SceUID sceKernelCreateThreadHookId = -1;
SceUID kermit_wait_and_get_request_hook_id = -1;

static int (*kermit_wait_and_get_request)(int type, SceKermitRequest **) = NULL;
int (*kermit_respond_request)(int type, SceKermitRequest *, uint64_t response) = NULL;
static void (*kermit_throw_error)(uint32_t error) = NULL;
static uint32_t (*kermit_swi_wait_get_request)(int type, uint32_t unk1, uint32_t unk2, uint32_t unk3) = NULL;
static uint32_t *kermit_state_1015C = NULL;
void *(*kermit_get_pspemu_addr_from_psp_addr)(uint32_t psp_addr, kermit_addr_mode mode, uint32_t size) = NULL;
int (*kermit_pspemu_writeback_cache)(void *addr, int size) = NULL;

int kermit_wait_and_get_request_new(int type, SceKermitRequest **request){
	uint32_t unknown_1;
	if (type == 5){
		unknown_1 = 1;
	}else if (type == 6){
		unknown_1 = 2;
	}else{
		unknown_1 = 0;
	}

	//LOG("%s: kermit_state_1015C 0x%x, kermit_swi_wait_get_request 0x%x\n", __func__, *kermit_state_1015C, kermit_swi_wait_get_request);

	//LOG("%s: doing swi with type 0x%x\n", __func__, type);

	uint32_t unknown_2 = kermit_swi_wait_get_request(type, unknown_1, 0, 0);

	//LOG("%s: swi done with result 0x%x\n", __func__, unknown_2);

	if ((int32_t)unknown_2 < 0){
		LOG("%s: throwing kermit_swi_wait_get_request error 0x%x\n", __func__, unknown_2);
		kermit_throw_error(unknown_2);
		*request = 0;
		return 0;
	}

	uint32_t unknown_3 = unknown_2 * 2 & 0x1fffffff;
	if (unknown_3 + 0xf8000000 < 0x4000000){
		if (((int)(unknown_2 * 2) < 1) || (unknown_3 + 0xf7c00000 < 0x7000000)) {
			*request = (SceKermitRequest *)(unknown_3 + *kermit_state_1015C - 0x8000000);
			return request[0]->cmd;
		}
	}else{
		if (unknown_3 + 0xfc000000 < 0x800000){
			*request = (SceKermitRequest *)(unknown_3 + *kermit_state_1015C - 0x200000);
			return request[0]->cmd;
		}
		if (unknown_3 - 0x10000 < 0x4000) {
			*request = (SceKermitRequest *)(unknown_3 + *kermit_state_1015C + 0x3cf0000);
			return request[0]->cmd;
		}
	}
	LOG("%s: wait failed, trigger null pointer deref like the original\n", __func__);
	*request = 0;
	return request[0]->cmd;
}

int kermit_wait_and_get_request_patched(int type, SceKermitRequest **request){
	while(1){
		// Register/branch inconsistency on this hook, we can't use the trampoline from taihen here
		//int cmd = TAI_CONTINUE(int, kermit_wait_and_get_request_ref);

		int cmd = kermit_wait_and_get_request_new(type, request);

		if (type == KERMIT_MODE_WLAN){
			int handled = handle_inet_request(*request);
			if (handled){
				continue;
			}
		}

		return cmd;
	}

	return 0;
}

static SceUID sceKernelCreateThreadPatched(const char *name, SceKernelThreadEntry entry, int initPriority,
                      int stackSize, SceUInt attr, int cpuAffinityMask,
                      const SceKernelThreadOptParam *option) {
	LOG("%s: starting thread %s with entry 0x%x\n", __func__, name, entry);

	int result = TAI_CONTINUE(SceUID, sceKernelCreateThreadRef, name, entry, initPriority, stackSize, attr, cpuAffinityMask, option);
	return result;
}

static void dump_pspemu(SceUID modid){
	SceKernelModuleInfo modinfo;
	modinfo.size = sizeof(modinfo);
	int get_module_status = sceKernelGetModuleInfo(modid, &modinfo);
	if (get_module_status != 0){
		LOG("%s: failed getting module info, 0x%x\n", __func__, get_module_status);
		return;
	}

	for (int i = 0;i < 4;i++){
		LOG("%s: seg num %d size %d vaddr 0x%x memsz %d\n", __func__, i, modinfo.segments[i].size, modinfo.segments[i].vaddr, modinfo.segments[i].memsz);
		if (modinfo.segments[i].size != 0){
			char path[256];
			sprintf(path, "ux0:/pspemu_seg_%d.dump", i);
			int fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
			if (fd < 0){
				LOG("%s: failed opening %s for writing, 0x%x\n", __func__, path, fd);
				continue;
			}
			int write_status = sceIoWrite(fd, modinfo.segments[i].vaddr, modinfo.segments[i].memsz);
			sceIoClose(fd);
		}
	}
}

// offsets are from 3.65
static int get_functions_and_data(SceUID modid){
	SceKernelModuleInfo modinfo;
	modinfo.size = sizeof(modinfo);
	int get_module_status = sceKernelGetModuleInfo(modid, &modinfo);
	if (get_module_status != 0){
		LOG("%s: failed getting module info, 0x%x\n", __func__, get_module_status);
		return -1;
	}

	uint32_t text_addr = (uint32_t)modinfo.segments[0].vaddr;
	uint32_t data_addr = (uint32_t)modinfo.segments[1].vaddr;

	kermit_wait_and_get_request = (void *)(text_addr + 0x64D0 + 0x1);
	kermit_respond_request = (void *)(text_addr + 0x6560 + 0x1);
	kermit_throw_error = (void *)(text_addr + 0x4104 + 0X1);
	kermit_swi_wait_get_request = (void *)(text_addr + 0x6F7C);
	kermit_state_1015C = (void *)(data_addr + 0x1015c);
	kermit_get_pspemu_addr_from_psp_addr = (void *)(text_addr + 0x6364 + 0x1);
	kermit_pspemu_writeback_cache = (void *)(text_addr + 0x6490 + 0x1);
	sceNetSyscallIoctl_import = (void *)(text_addr + 0x729c);

	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start"))); 
int module_start(SceSize args, void *argp) {
	int ret = 0;

	tai_module_info_t tai_info;
	tai_info.size = sizeof(tai_module_info_t);
	
	ret = taiGetModuleInfo("ScePspemu", &tai_info);
	if (ret < 0){
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	LOG_INIT();

	int module_load_status = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
	if (module_load_status < 0){
		LOG("%s: failed loading inet module, 0x%x\n", __func__, module_load_status);
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	#if DUMP
	dump_pspemu(tai_info.modid);
	sceKernelCreateThreadHookId = taiHookFunctionImport(&sceKernelCreateThreadRef, "ScePspemu", 0xCAE9ACE6, 0xC5C11EE7, sceKernelCreateThreadPatched);
	LOG("%s: sceKernelCreateThread hooked 0x%x\n", __func__, sceKernelCreateThreadHookId);
	#endif

	get_functions_and_data(tai_info.modid);
	kermit_wait_and_get_request_hook_id = taiHookFunctionOffset(&kermit_wait_and_get_request_ref, tai_info.modid, 0, 0x64D0, 1, kermit_wait_and_get_request_patched);
	LOG("%s: kermit_wait_and_get_request hooked 0x%x\n", __func__, kermit_wait_and_get_request_hook_id);

	int workers_started = inet_init();
	LOG("%s: started %d workers\n", __func__, workers_started);

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
	#if DUMP
	taiHookRelease(sceKernelCreateThreadHookId, sceKernelCreateThreadRef);
	LOG("%s: sceKernelCreateThread unhooked\n", __func__);
	#endif
	taiHookRelease(kermit_wait_and_get_request_hook_id, kermit_wait_and_get_request_ref);

	return SCE_KERNEL_STOP_SUCCESS;
}
