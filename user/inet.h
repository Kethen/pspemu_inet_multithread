#ifndef __INET_H
#define __INET_H
int handle_inet_request(SceKermitRequest *request);
int inet_init();

extern int (*sceNetSyscallIoctl_import)(int sockfd, uint32_t command, void *data);
#endif
