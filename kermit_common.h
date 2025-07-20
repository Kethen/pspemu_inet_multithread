#ifndef __KERMIT_COMMON_H
#define __KERMIT_COMMON_H

// based on https://github.com/TheOfficialFlow/Adrenaline/blob/master/adrenaline_compat.h
// https://github.com/TheOfficialFloW/Adrenaline/blob/master/user/main.c
typedef struct {
	uint32_t cmd; //0x0
	int32_t sema_id; //0x4
	uint64_t *response; //0x8
	uint32_t padding; //0xC
	uint64_t args[14]; // 0x10
} SceKermitRequest; //0x80

struct request_slot{
	uint32_t mode;
	uint32_t cmd;
	int32_t in_use;
	int32_t done;
	uint64_t args[14];
	uint64_t ret;
	char buf[sizeof(SceKermitRequest) + 0x40];
};

#define KERMIT_MODE_WLAN 10

typedef enum kermit_wlan_custom_command{
	KERMIT_INET_SOCKET = 1,
	KERMIT_INET_BIND,
	KERMIT_INET_LISTEN,
	KERMIT_INET_ACCEPT,
	KERMIT_INET_CONNECT,
	KERMIT_INET_SETSOCKOPT,
	KERMIT_INET_GETSOCKOPT,
	KERMIT_INET_GETSOCKNAME,
	KERMIT_INET_GETPEERNAME,
	KERMIT_INET_SEND,
	KERMIT_INET_SENDTO,
	KERMIT_INET_SENDMSG,
	KERMIT_INET_RECV,
	KERMIT_INET_RECVFROM,
	KERMIT_INET_RECVMSG,
	KERMIT_INET_CLOSE,
	KERMIT_INET_POLL,
	KERMIT_INET_SELECT,
	KERMIT_INET_CLOSE_WITH_RST,
	KERMIT_INET_SOCKET_ABORT,
}kermit_wlan_custom_command;

#endif
