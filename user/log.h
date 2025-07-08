#ifndef __LOG_H
#define __LOG_H

#define LOG(...) { \
	sceClibPrintf(__VA_ARGS__); \
}

#endif
