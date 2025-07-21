#include <pspsdk.h>
#include <psputilsforkernel.h>
#include <pspthreadman.h>

#include <string.h>
#include <stdbool.h>

#include "log.h"
#include "hen.h"
#include "hooking.h"
#include "kermit.h"

PSP_MODULE_INFO("pspnet_inet_kermit_redirect", PSP_MODULE_KERNEL, 1, 0);

STMOD_HANDLER last_handler = NULL;

struct errno_slot{
	int tid;
	int errno;
	uint64_t last_update;
};

uint32_t nbio_field[8] = {0};
struct errno_slot errnos[64] = {0};

static int psp_select_fd_is_set(uint32_t *field, int sockfd){
	return field[sockfd >> 5] & (1 << (sockfd & 0x1f));
}

static void psp_select_set_fd(uint32_t *field, int sockfd, bool set){
	if (set) {
		field[sockfd >> 5] |= 1 << (sockfd & 0x1f);
	}else{
		field[sockfd >> 5] &= ~(1 << (sockfd & 0x1f));
	}
}

static int extract_result_and_save_errno(uint64_t error_res){
	int32_t *val = (int32_t *)&error_res;
	int tid = sceKernelGetThreadId();
	int empty_slot = -1;
	int oldest_slot = -1;
	for(int i = 0;i < sizeof(errnos) / sizeof(struct errno_slot);i++){
		if (empty_slot == -1 && errnos[i].tid){
			empty_slot = i;
		}
		if (oldest_slot == -1 || errnos[oldest_slot].last_update > errnos[i].last_update){
			oldest_slot = i;
		}
		if (errnos[i].tid == tid){
			errnos[i].errno = val[0];
			errnos[i].last_update = sceKernelGetSystemTimeWide();
			return val[1];
		}
	}

	if (empty_slot != -1){
		errnos[empty_slot].tid = tid;
		errnos[empty_slot].errno = val[0];
		errnos[empty_slot].last_update = sceKernelGetSystemTimeWide();
		return val[1];
	}

	errnos[oldest_slot].tid = tid;
	errnos[oldest_slot].errno = val[0];
	errnos[oldest_slot].last_update = sceKernelGetSystemTimeWide();
	return val[1];
}

int sceNetInetSocketPatched(int domain, int type, int protocol){
	//LOG("%s: begin\n", __func__);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET, 0, (int64_t)domain, (int64_t)type, (int64_t)protocol);

	int result = extract_result_and_save_errno(res);
	if (result >= 0){
		psp_select_set_fd(nbio_field, result, false);
	}
	return result;
}

int sceNetInetBindPatched(int sockfd, void *sockaddr, int addrlen){
	sceKernelDcacheWritebackInvalidateRange(sockaddr, addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_BIND, 0, (int64_t)sockfd, (uint64_t)sockaddr, (int64_t)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetListenPatched(int sockfd, int backlog){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_LISTEN, 0, (int64_t)sockfd, (int64_t)backlog);
	return extract_result_and_save_errno(res);
}

int sceNetInetAcceptPatched(int sockfd, void *sockaddr, void *addrlen){
	if (addrlen != NULL)
		sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	if (sockaddr != NULL)
		sceKernelDcacheWritebackInvalidateRange(sockaddr, *(int32_t*)addrlen);

	int nbio = psp_select_fd_is_set(nbio_field, sockfd);

	uint64_t res = kermit_send_wlan_request(KERMIT_INET_ACCEPT, nbio, (int64_t)sockfd, (uint64_t)sockaddr, (uint64_t)addrlen);

	if (addrlen != NULL)
		sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	if (sockaddr != NULL)
		sceKernelDcacheWritebackInvalidateRange(sockaddr, *(int32_t*)addrlen);

	return extract_result_and_save_errno(res);
}

int sceNetInetConnectPatched(int sockfd, void *sockaddr, int addrlen){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);

	sceKernelDcacheWritebackInvalidateRange(sockaddr, addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CONNECT, nbio, (int64_t)sockfd, (uint64_t)sockaddr, (int64_t)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetSetsockoptPatched(int sockfd, int level, int optname, void *optval, int optlen){
	sceKernelDcacheWritebackInvalidateRange(optval, optlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SETSOCKOPT, 0, (int64_t)sockfd, (int64_t)level, (int64_t)optname, (uint64_t)optval, (int64_t)optlen);
	int result = extract_result_and_save_errno(res);

	if (result >= 0 && level == 0xffff && optname == 0x1009){
		int optval_content = 0;
		if (optlen == 8){
			optval_content = *(uint8_t*)optval;
		}else if (optlen == 16){
			optval_content = *(uint16_t*)optval;
		}else{
			optval_content = *(uint32_t*)optval;
		}
		psp_select_set_fd(nbio_field, sockfd, optval_content);
	}

	return result;
}

int sceNetInetGetsockoptPatched(int sockfd, int level, int optname, void *optval, void *optlen){
	sceKernelDcacheWritebackInvalidateRange(optlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(optval, *(int32_t*)optlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETSOCKOPT, 0, (int64_t)sockfd, (int64_t)level, (int64_t)optname, (uint64_t)optval, (uint64_t)optlen);
	sceKernelDcacheWritebackInvalidateRange(optlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(optval, *(int32_t*)optlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetGetsocknamePatched(int sockfd, void *addr, void *addrlen){
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETSOCKNAME, 0, (int64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen);
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetGetpeernamePatched(int sockfd, void *addr, void *addrlen){
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETPEERNAME, 0, (int64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen);
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetSendPatched(int sockfd, void *buf, int size, int flags){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);
	if (flags & 0x80){
		nbio = 1;
	}

	sceKernelDcacheWritebackInvalidateRange(buf, size);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SEND, nbio, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags);
	return extract_result_and_save_errno(res);
}

int sceNetInetSendtoPatched(int sockfd, void *buf, int size, int flags, void *dest_addr, int addrlen){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);
	if (flags & 0x80){
		nbio = 1;
	}

	sceKernelDcacheWritebackInvalidateRange(buf, size);
	sceKernelDcacheWritebackInvalidateRange(dest_addr, addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SENDTO, nbio, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags, (uint64_t)dest_addr, (int64_t)addrlen);
	return extract_result_and_save_errno(res);
}

// these structs are from vitasdk https://github.com/vitasdk/vita-headers/blob/master/include/psp2common/net.h
struct SceNetIovec {
	void *iov_base;
	unsigned int iov_len;
} SceNetIovec;

struct SceNetMsghdr {
	void *msg_name;
	unsigned int msg_namelen;
	struct SceNetIovec *msg_iov;
	int msg_iovlen;
	void *msg_control;
	unsigned int msg_controllen;
	int msg_flags;
} SceNetMsghdr;

int sceNetInetSendmsgPatched(int sockfd, struct SceNetMsghdr *msg, int flags){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);
	if (flags & 0x80){
		nbio = 1;
	}

	sceKernelDcacheWritebackInvalidateRange(msg, sizeof(SceNetMsghdr));
	if (msg->msg_name != NULL && msg->msg_namelen != 0){
		sceKernelDcacheWritebackInvalidateRange(msg->msg_name, msg->msg_namelen);
	}
	if (msg->msg_iovlen != 0 && msg->msg_iov != NULL){
		for(int i = 0;i < msg->msg_iovlen;i++){
			sceKernelDcacheWritebackInvalidateRange(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		}
	}
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SENDMSG, nbio, (int64_t)sockfd, (uint64_t)msg, (int64_t)flags);
	return extract_result_and_save_errno(res);
}

int sceNetInetRecvPatched(int sockfd, void *buf, int size, int flags){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);
	if (flags & 0x80){
		nbio = 1;
	}

	sceKernelDcacheWritebackInvalidateRange(buf, size);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_RECV, nbio, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags);
	sceKernelDcacheWritebackInvalidateRange(buf, size);
	return extract_result_and_save_errno(res);
}

int sceNetInetRecvfromPatched(int sockfd, void *buf, int size, int flags, void *dest_addr, void *addrlen){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);
	if (flags & 0x80){
		nbio = 1;
	}

	sceKernelDcacheWritebackInvalidateRange(buf, size);
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(dest_addr, *(int32_t*)addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_RECVFROM, nbio, (int64_t)sockfd, (uint64_t)buf, (int64_t)size, (int64_t)flags, (uint64_t)dest_addr, (uint64_t)addrlen);
	sceKernelDcacheWritebackInvalidateRange(buf, size);
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(dest_addr, *(int32_t*)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetRecvmsgPatched(int sockfd, struct SceNetMsghdr *msg, int flags){
	int nbio = psp_select_fd_is_set(nbio_field, sockfd);
	if (flags & 0x80){
		nbio = 1;
	}

	sceKernelDcacheWritebackInvalidateRange(msg, sizeof(SceNetMsghdr));
	if (msg->msg_name != NULL && msg->msg_namelen != 0){
		sceKernelDcacheWritebackInvalidateRange(msg->msg_name, msg->msg_namelen);
	}
	if (msg->msg_iovlen != 0 && msg->msg_iov != NULL){
		for(int i = 0;i < msg->msg_iovlen;i++){
			sceKernelDcacheWritebackInvalidateRange(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		}
	}
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_RECVMSG, nbio, (int64_t)sockfd, (uint64_t)msg, (int64_t)flags);
	sceKernelDcacheWritebackInvalidateRange(msg, sizeof(SceNetMsghdr));
	if (msg->msg_name != NULL && msg->msg_namelen != 0){
		sceKernelDcacheWritebackInvalidateRange(msg->msg_name, msg->msg_namelen);
	}
	if (msg->msg_iovlen != 0 && msg->msg_iov != NULL){
		for(int i = 0;i < msg->msg_iovlen;i++){
			sceKernelDcacheWritebackInvalidateRange(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		}
	}
	return extract_result_and_save_errno(res);
}

int sceNetInetClosePatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CLOSE, 0, (int64_t)sockfd);
	return extract_result_and_save_errno(res);
}

struct psp_poll_fd{
	int sockfd;
	int16_t events;
	int16_t revents;
};

int sceNetInetPollPatched(struct psp_poll_fd *fds, unsigned int nfds, int timeout){
	sceKernelDcacheWritebackInvalidateRange(fds, sizeof(struct psp_poll_fd) * nfds);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_POLL, 0, (uint64_t)fds, (uint64_t)nfds, (int64_t)timeout);
	sceKernelDcacheWritebackInvalidateRange(fds, sizeof(struct psp_poll_fd) * nfds);
	return extract_result_and_save_errno(res);
}

int sceNetInetSelectPatched(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout){
	if (readfds != NULL)
		sceKernelDcacheWritebackInvalidateRange(readfds, 256);
	if (writefds != NULL)
		sceKernelDcacheWritebackInvalidateRange(writefds, 256);
	if (exceptfds != NULL)
		sceKernelDcacheWritebackInvalidateRange(exceptfds, 256);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SELECT, 0, (int64_t)nfds, (uint64_t)readfds, (uint64_t)writefds, (uint64_t)exceptfds, (uint64_t)timeout);
	if (readfds != NULL)
		sceKernelDcacheWritebackInvalidateRange(readfds, 256);
	if (writefds != NULL)
		sceKernelDcacheWritebackInvalidateRange(writefds, 256);
	if (exceptfds != NULL)
		sceKernelDcacheWritebackInvalidateRange(exceptfds, 256);
	return extract_result_and_save_errno(res);
}

int sceNetInetCloseWithRSTPatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CLOSE_WITH_RST, 0, (int64_t)sockfd);
	return extract_result_and_save_errno(res);
}

int sceNetInetSocketAbortPatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET_ABORT, 0, (int64_t)sockfd);
	return extract_result_and_save_errno(res);
}

int sceNetInetGetErrnoPatched(){
	int tid = sceKernelGetThreadId();
	for (int i = 0;i < sizeof(errnos) / sizeof(struct errno_slot);i++){
		if (errnos[i].tid == tid){
			return errnos[i].errno;
		}
	}
	LOG("%s: warning, errno not found for thread %d\n", __func__, tid);
	return 0;
}

SceModule2 game_module;
bool game_module_found = false;
SceModule2 adhoc_module;
bool adhoc_module_found = false;
SceModule2 adhocctl_module;
bool adhocctl_module_found = false;
SceModule2 upnp_module;
bool upnp_module_found = false;

int sceKernelQuerySystemCall(void *function);

static void replace_import(PspModuleImport *import, uint32_t nid, void *function){
	int syscall = sceKernelQuerySystemCall(function);
	if (syscall < 0){
		LOG("%s: bad syscall, fix the export on nid 0x%x\n", __func__, nid);
		return;
	}
	for(int i = 0;i < import->funcCount;i++){
		if (import->fnids[i] == nid){
			uint32_t *addr = (uint32_t *)&import->funcs[i * 2];

			int _interrupts = pspSdkDisableInterrupts();
			uint32_t orig_instructions[2] = {addr[0], addr[1]};
			addr[0] = 0x03E00008; // jr
			addr[1] = 0x0000000C | (syscall << 6); //syscall
			sceKernelDcacheWritebackInvalidateRange(addr, 8);
			sceKernelIcacheInvalidateRange(addr, 8);
			pspSdkEnableInterrupts(_interrupts);
			LOG("%s: 0x%x 0x%x -> 0x%x 0x%x (0x%x)\n", __func__, orig_instructions[0], orig_instructions[1], addr[0], addr[1], syscall);
			return;
		}
	}
	LOG("%s: nid 0x%x not found\n", __func__, nid);
}

static void replace_functions(SceModule2 *mod){
		PspModuleImport *inet_import = NULL;
		int i = 0;
		while (i < mod->stub_size){
			PspModuleImport *import = (PspModuleImport *)(mod->stub_top + i);
			if (import->name == NULL){
				i += import->entLen * 4;
				continue;
			}
			if (strcmp(import->name, "sceNetInet") == 0){
				inet_import = import;
				break;
			}
			i += import->entLen * 4;
		}

		if (inet_import == NULL){
			LOG("%s: module %s does not seem to import inet, not patching\n", __func__, mod->modname);
			return;
		}

		#define STR(s) #s
		#define REPLACE_FUNCTION(_name, _nid) \
			LOG("%s: replacing %s\n", __func__, STR(_name)); \
			replace_import(inet_import, _nid, _name##Patched);

		// mostly standard unix socket
		REPLACE_FUNCTION(sceNetInetSocket, 0x8B7B220F);
		REPLACE_FUNCTION(sceNetInetBind, 0x1A33F9AE);
		REPLACE_FUNCTION(sceNetInetListen, 0xD10A1A7A);
		REPLACE_FUNCTION(sceNetInetAccept, 0xDB094E1B);
		REPLACE_FUNCTION(sceNetInetConnect, 0x410B34AA);
		REPLACE_FUNCTION(sceNetInetSetsockopt, 0x2FE71FE7);
		REPLACE_FUNCTION(sceNetInetGetsockopt, 0x4A114C7C);
		REPLACE_FUNCTION(sceNetInetGetsockname, 0x162E6FD5);
		REPLACE_FUNCTION(sceNetInetGetpeername, 0xE247B6D6);
		REPLACE_FUNCTION(sceNetInetSend, 0x7AA671BC);
		REPLACE_FUNCTION(sceNetInetSendto, 0x05038FC7);
		REPLACE_FUNCTION(sceNetInetSendmsg, 0x774E36F4);
		REPLACE_FUNCTION(sceNetInetRecv, 0xCDA85C99);
		REPLACE_FUNCTION(sceNetInetRecvfrom, 0xC91142E4);
		REPLACE_FUNCTION(sceNetInetRecvmsg, 0xEECE61D2);
		REPLACE_FUNCTION(sceNetInetClose, 0x8D7284EA);
		REPLACE_FUNCTION(sceNetInetPoll, 0xFAABB1DD);
		REPLACE_FUNCTION(sceNetInetSelect, 0x5BE8D595);

		// sony stuffs
		REPLACE_FUNCTION(sceNetInetCloseWithRST, 0x805502DD);
		REPLACE_FUNCTION(sceNetInetSocketAbort, 0x80A21ABD);
		REPLACE_FUNCTION(sceNetInetGetErrno, 0xFBABE411);

		#undef STR
		#undef REPLACE_FUNCTION
}

void rehook_inet(){
	LOG("%s: inet rehook triggered\n", __func__);
	if (adhoc_module_found){
		LOG("%s: hooking adhoc module\n", __func__);
		replace_functions(&adhoc_module);
	}
	if (adhocctl_module_found){
		LOG("%s: hooking adhocctl module\n", __func__);
		replace_functions(&adhocctl_module);
	}
	if (upnp_module_found){
		LOG("%s: hooking upnp module\n", __func__);
		replace_functions(&upnp_module);
	}
	if (game_module_found){
		replace_functions(&game_module);
	}
}

int apply_patch(SceModule2 *mod){
	if (mod->text_addr > 0x08800000 && mod->text_addr < 0x08900000 && strcmp("opnssmp", mod->modname) != 0){
		LOG("%s: guessing this is the game, %s, saving module info for later\n", __func__, mod->modname);
		game_module = *mod;
		game_module_found = true;

		if (last_handler != NULL){
			return last_handler(mod);
		}
		return 0;
	}

	if (strcmp(mod->modname, "sceNetAdhoc_Library") == 0){
		LOG("%s: keeping track of adhoc module in case it is aemu\n", __func__);
		adhoc_module = *mod;
		adhoc_module_found = true;

		if (last_handler != NULL){
			return last_handler(mod);
		}
		return 0;
	}

	if (strcmp(mod->modname, "sceNetAdhocctl_Library") == 0){
		LOG("%s: keeping track of adhocctl module in case it is aemu\n", __func__);
		adhocctl_module = *mod;
		adhocctl_module_found = true;

		if (last_handler != NULL){
			return last_handler(mod);
		}
		return 0;
	}

	if (strcmp(mod->modname, "sceNetMiniUPnP") == 0){
		LOG("%s: keeping track of miniupnc module for aemu\n", __func__);
		upnp_module = *mod;
		upnp_module_found = true;

		if (last_handler != NULL){
			return last_handler(mod);
		}
		return 0;
	}

	if (strcmp(mod->modname, "sceNetInet_Library") == 0){
		rehook_inet();
	}

	if (last_handler != NULL){
		return last_handler(mod);
	}
	return 0;
}

int module_start(SceSize args, void * argp){
	INIT_LOG();

	LOG("%s: begin\n", __func__);

	for (int i = 0;i < sizeof(errnos) / sizeof(struct errno_slot);i++){
		errnos[i].tid = -1;
	}

	last_handler = sctrlHENSetStartModuleHandler(apply_patch);

	return 0;
}

int module_stop(SceSize args, void * argp){
	LOG("%s: begin\n", __func__);
	return 0;
}
