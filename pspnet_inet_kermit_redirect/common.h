#ifndef __COMMON_H
#define __COMMON_H

#include <psputilsforkernel.h>
#include <pspthreadman.h>

#define CACHE_BARRIER() \
	asm volatile ("" : : : "memory"); \
	sceKernelDelayThread(50); \
	asm volatile ("" : : : "memory");

#endif
