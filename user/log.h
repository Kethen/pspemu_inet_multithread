#ifndef __LOG_H
#define __LOG_H

#include <psp2common/kernel/iofilemgr.h>

#include <stdio.h>

#define LOG_PATH "ux0:/pspemu_inet_multithread.log"

#define LOG_INIT() { \
	sceIoRemove(LOG_PATH); \
}

#define LOG(...) { \
	sceClibPrintf(__VA_ARGS__); \
	int _log_fd = sceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_APPEND | SCE_O_CREAT, 0777); \
	if (_log_fd >= 0){ \
		char _log_buf[1024]; \
		int _log_len = sprintf(_log_buf, __VA_ARGS__); \
		sceIoWrite(_log_fd, _log_buf, _log_len); \
		sceIoClose(_log_fd); \
	} \
}

#endif
