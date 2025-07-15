#include <pspsdk.h>

#include <string.h>

#include "log.h"
#include "hen.h"
#include "hooking.h"
#include "kermit.h"

PSP_MODULE_INFO("pspnet_inet_kermit_redirect", PSP_MODULE_KERNEL, 1, 0);

STMOD_HANDLER last_handler = NULL;

int sceNetInetSocketPatched(int domain, int type, int protocol){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET, (int64_t)domain, (int64_t)type, (int64_t)protocol);
	return *(int64_t *)&res;
}

int sceNetInetBindPatched(int sockfd, void *sockaddr, int addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_BIND, (int64_t)sockfd, (uint64_t)sockaddr, (int64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetListenPatched(int sockfd, int backlog){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_LISTEN, (int64_t)sockfd, (int64_t)backlog);
	return *(int64_t *)&res;
}

int sceNetInetAcceptPatched(int sockfd, void *sockaddr, void *addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_ACCEPT, (int64_t)sockfd, (uint64_t)sockaddr, (uint64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetConnectPatched(int sockfd, void *sockaddr, int addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CONNECT, (int64_t)sockfd, (uint64_t)sockaddr, (int64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetSetsockoptPatched(int sockfd, int level, int optname, void *optval, int optlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SETSOCKOPT, (int64_t)sockfd, (int64_t)level, (int64_t)optname, (uint64_t)optval, (int64_t)optlen);
	return *(int64_t *)&res;
}

int sceNetInetGetsockoptPatched(int sockfd, int level, int optname, void *optval, void *optlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETSOCKOPT, (int64_t)sockfd, (int64_t)level, (int64_t)optname, (uint64_t)optval, (uint64_t)optlen);
	return *(int64_t *)&res;
}

int sceNetInetGetsocknamePatched(int sockfd, void *addr, void *addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETSOCKNAME, (int64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetGetpeernamePatched(int sockfd, void *addr, void *addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETPEERNAME, (int64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetSendPatched(int sockfd, void *buf, int size, int flags){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SEND, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags);
	return *(int64_t *)&res;
}

int sceNetInetSendtoPatched(int sockfd, void *buf, int size, int flags, void *dest_addr, int addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SENDTO, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags, (uint64_t)dest_addr, (int64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetSendmsgPatched(int sockfd, void *msg, int flags){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SENDMSG, (int64_t)sockfd, (uint64_t)msg, (int64_t)flags);
	return *(int64_t *)&res;
}

int sceNetInetRecvPatched(int sockfd, void *buf, int size, int flags){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_RECV, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags);
	return *(int64_t *)&res;
}

int sceNetInetRecvfromPatched(int sockfd, void *buf, int size, int flags, void *dest_addr, void *addrlen){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_RECVFROM, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags, (uint64_t)dest_addr, (uint64_t)addrlen);
	return *(int64_t *)&res;
}

int sceNetInetRecvmsgPatched(int sockfd, void *msg, int flags){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_RECVMSG, (int64_t)sockfd, (uint64_t)msg, (int64_t)flags);
	return *(int64_t *)&res;
}

int sceNetInetClosePatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CLOSE, (int64_t)sockfd);
	return *(int64_t *)&res;
}

int sceNetInetPollPatched(void *fds, unsigned int nfds, int timeout){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_POLL, (uint64_t)fds, (uint64_t)nfds, (int64_t)timeout);
	return *(int64_t *)&res;
}

int sceNetInetSelectPatched(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SELECT, (int64_t)nfds, (uint64_t)readfds, (uint64_t)writefds, (uint64_t)exceptfds, (uint64_t)timeout);
	return *(int64_t *)&res;
}

int sceNetInetCloseWithRSTPatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CLOSE_WITH_RST, (int64_t)sockfd);
	return *(int64_t *)&res;
}

int sceNetInetSocketAbortPatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET_ABORT, (int64_t)sockfd);
	return *(int64_t *)&res;
}

int apply_patch(SceModule2 *mod){
	if (strcmp(mod->modname, "sceNetInet_Library") == 0){
		#define STR(s) #s
		#define SEARCH_AND_HIJACK(_name, _nid) \
			u32 _name##Ref = sctrlHENFindFunction("sceNetInet_Library", "sceNetInet", _nid); \
			LOG("%s: %s ref 0x%x\n", __func__, STR(_name), _name##Ref); \
			HIJACK_FUNCTION(_name##Ref, _name##Patched, orig, 1);

		// socket functions that very likely needs to be wrapped

		// probably discarding the originals for now
		void *orig;

		// mostly standard unix socket
		SEARCH_AND_HIJACK(sceNetInetSocket, 0x8B7B220F);
		SEARCH_AND_HIJACK(sceNetInetBind, 0x1A33F9AE);
		SEARCH_AND_HIJACK(sceNetInetListen, 0xD10A1A7A);
		SEARCH_AND_HIJACK(sceNetInetAccept, 0xDB094E1B);
		SEARCH_AND_HIJACK(sceNetInetConnect, 0x410B34AA);
		SEARCH_AND_HIJACK(sceNetInetSetsockopt, 0x2FE71FE7);
		SEARCH_AND_HIJACK(sceNetInetGetsockopt, 0x4A114C7C);
		SEARCH_AND_HIJACK(sceNetInetGetsockname, 0x162E6FD5);
		SEARCH_AND_HIJACK(sceNetInetGetpeername, 0xE247B6D6);
		SEARCH_AND_HIJACK(sceNetInetSend, 0x7AA671BC);
		SEARCH_AND_HIJACK(sceNetInetSendto, 0x05038FC7);
		SEARCH_AND_HIJACK(sceNetInetSendmsg, 0x774E36F4);
		SEARCH_AND_HIJACK(sceNetInetRecv, 0xCDA85C99);
		SEARCH_AND_HIJACK(sceNetInetRecvfrom, 0xC91142E4);
		SEARCH_AND_HIJACK(sceNetInetRecvmsg, 0xEECE61D2);
		SEARCH_AND_HIJACK(sceNetInetClose, 0x8D7284EA);
		SEARCH_AND_HIJACK(sceNetInetPoll, 0x5BE8D595);
		SEARCH_AND_HIJACK(sceNetInetSelect, 0x5BE8D595);

		// sony stuffs
		SEARCH_AND_HIJACK(sceNetInetCloseWithRST, 0x805502DD);
		SEARCH_AND_HIJACK(sceNetInetSocketAbort, 0x80A21ABD);

		#undef STR
		#undef SEARCH_AND_HIJACK
	}

	if (last_handler != NULL){
		return last_handler(mod);
	}
	return 0;
}

int module_start(SceSize args, void * argp){
	INIT_LOG();

	last_handler = sctrlHENSetStartModuleHandler(apply_patch);

	LOG("%s: begin\n", __func__);
	return 0;
}

int module_stop(SceSize args, void * argp){
	LOG("%s: begin\n", __func__);
	return 0;
}
