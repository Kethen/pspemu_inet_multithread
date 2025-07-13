#ifndef __LOG_H
#define __LOG_H

#include <pspdebug.h>
#include <pspiofilemgr.h>
#include <stdio.h>

#define LOG(...){ \
	int _log_fd = sceIoOpen("ms0:/wlan_test_log.log", PSP_O_CREAT | PSP_O_APPEND | PSP_O_WRONLY, 0777); \
	if (_log_fd < 0){ \
		_log_fd = sceIoOpen("ef0:/wlan_test_log.log", PSP_O_CREAT | PSP_O_APPEND | PSP_O_WRONLY, 0777); \
	} \
	if (_log_fd > 0){ \
		char _log_buf[1024]; \
		int _len = sprintf(_log_buf, __VA_ARGS__); \
		sceIoWrite(_log_fd, _log_buf, _len); \
		sceIoClose(_log_fd); \
		_log_fd = -1; \
	} \
	pspDebugScreenPrintf(__VA_ARGS__); \
}

#define INIT_LOG(){ \
	pspDebugScreenInit(); \
	sceIoRemove("ms0:/wlan_test_log.log"); \
	sceIoRemove("ef0:/wlan_test_log.log"); \
}

#endif
