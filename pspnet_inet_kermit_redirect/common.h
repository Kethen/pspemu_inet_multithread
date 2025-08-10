#ifndef __COMMON_H
#define __COMMON_H

#include <psputilsforkernel.h>
#include <pspthreadman.h>

void unlock_transmit_mutex();
void lock_transmit_mutex();

#define CACHE_BARRIER() \
	asm volatile ("" : : : "memory"); \
	sceKernelDelayThread(50); \
	asm volatile ("" : : : "memory");

#endif
