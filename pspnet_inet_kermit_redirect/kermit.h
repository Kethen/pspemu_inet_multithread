#ifndef __KERMIT_H
#define __KERMIT_H

#include <pspthreadman.h>

#include "../kermit_common.h"

extern SceUID request_slots_mutex;

uint64_t _kermit_send_request(uint32_t mode, uint32_t cmd, int num_args, int nbio, ...);
#define kermit_send_request(mode, cmd, nbio, ...) _kermit_send_request(mode, cmd, sizeof((uint64_t[]){__VA_ARGS__}) / sizeof(uint64_t), nbio, __VA_ARGS__)
#define kermit_send_wlan_request(...) kermit_send_request(KERMIT_MODE_WLAN, __VA_ARGS__)

#endif
