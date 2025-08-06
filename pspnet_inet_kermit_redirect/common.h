#ifndef __COMMON_H
#define __COMMON_H

#include <psputilsforkernel.h>
#include <pspthreadman.h>

#if 1
#define CACHE_BARRIER() \
	asm volatile ("" : : : "memory"); \
	sceKernelDelayThread(50); \
	asm volatile ("" : : : "memory");
#else
#define CACHE_BARRIER() asm volatile ("" : : : "memory");
#endif

#endif
