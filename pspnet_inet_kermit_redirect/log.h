#ifndef __LOG_H
#define __LOG_H

#include <pspsdk.h>
#include <pspiofilemgr.h>
#include <pspstdio.h>

#include <stdio.h>

#if 1

#define LOG(...){ \
	int _k1 = pspSdkSetK1(0); \
	int _log_fd = sceIoOpen("ms0:/pspnet_inet_kermit_redirect.log", PSP_O_CREAT | PSP_O_APPEND | PSP_O_WRONLY, 0777); \
	if (_log_fd < 0){ \
		_log_fd = sceIoOpen("ef0:/pspnet_inet_kermit_redirect.log", PSP_O_CREAT | PSP_O_APPEND | PSP_O_WRONLY, 0777); \
	} \
	if (_log_fd > 0){ \
		char _log_buf[256]; \
		int _len = sprintf(_log_buf, __VA_ARGS__); \
		sceIoWrite(_log_fd, _log_buf, _len); \
		sceIoClose(_log_fd); \
		_log_fd = -1; \
	} \
	pspSdkSetK1(_k1); \
}

#define INIT_LOG(){ \
	sceIoRemove("ms0:/pspnet_inet_kermit_redirect.log"); \
	sceIoRemove("ef0:/pspnet_inet_kermit_redirect.log"); \
}

#else

#define LOG(...)
#define INIT_LOG()

#endif

#endif
