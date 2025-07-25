#include <pspsdk.h>
#include <psputilsforkernel.h>
#include <pspthreadman.h>
#include <psputility_modules.h>
#include <psputility_netmodules.h>

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

SceModule2 game_module;
bool game_module_found = false;

struct tracked_module{
	SceModule2 mod;
	const char *name;
	bool found;
};

struct tracked_module tracked_modules[] = {
	{
		.mod = {0},
		.name = "sceNetAdhoc_Library",
		.found = false
	},
	{
		.mod = {0},
		.name = "sceNetAdhocctl_Library",
		.found = false
	},
	{
		.mod = {0},
		.name = "sceNetMiniUPnP",
		.found = false
	},

	#if 1
	{
		.mod = {0},
		.name = "sceNpMatching2",
		.found = false
	},
	{
		.mod = {0},
		.name = "sceSsl_Module",
		.found = false
	},
	{
		.mod = {0},
		.name = "SceHttp_Library",
		.found = false
	},
	{
		.mod = {0},
		.name = "sceDNAS_Library",
		.found = false
	},
	#endif

	#if 1
	{
		.mod = {0},
		.name = "sceNetResolver_Library",
		.found = false
	},
	{
		.mod = {0},
		.name = "sceNetUpnp_Library",
		.found = false
	}
	#endif
};

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
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET, 1, (int64_t)domain, (int64_t)type, (int64_t)protocol);

	int result = extract_result_and_save_errno(res);
	if (result >= 0){
		psp_select_set_fd(nbio_field, result, false);
	}
	return result;
}

int sceNetInetBindPatched(int sockfd, void *sockaddr, int addrlen){
	sceKernelDcacheWritebackInvalidateRange(sockaddr, addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_BIND, 1, (int64_t)sockfd, (uint64_t)sockaddr, (int64_t)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetListenPatched(int sockfd, int backlog){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_LISTEN, 1, (int64_t)sockfd, (int64_t)backlog);
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
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SETSOCKOPT, 1, (int64_t)sockfd, (int64_t)level, (int64_t)optname, (uint64_t)optval, (int64_t)optlen);
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
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETSOCKOPT, 1, (int64_t)sockfd, (int64_t)level, (int64_t)optname, (uint64_t)optval, (uint64_t)optlen);
	sceKernelDcacheWritebackInvalidateRange(optlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(optval, *(int32_t*)optlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetGetsocknamePatched(int sockfd, void *addr, void *addrlen){
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETSOCKNAME, 1, (int64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen);
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	return extract_result_and_save_errno(res);
}

int sceNetInetGetpeernamePatched(int sockfd, void *addr, void *addrlen){
	sceKernelDcacheWritebackInvalidateRange(addrlen, sizeof(int32_t));
	sceKernelDcacheWritebackInvalidateRange(addr, *(int32_t*)addrlen);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_GETPEERNAME, 1, (int64_t)sockfd, (uint64_t)addr, (uint64_t)addrlen);
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
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CLOSE, 1, (int64_t)sockfd);
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
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_CLOSE_WITH_RST, 1, (int64_t)sockfd);
	return extract_result_and_save_errno(res);
}

int sceNetInetSocketAbortPatched(int sockfd){
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET_ABORT, 1, (int64_t)sockfd);
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

uint32_t sceNetInetGetPspErrorPatched(){
	// there might be exceptions, but do this for now
	return (uint32_t)sceNetInetGetErrnoPatched() | 0x80010000;
}

// probably some kind of internal ioctl
uint32_t sceNetInet_lib_AEE60F84_patched(int sockfd, uint32_t command, void *data){
	if (data != NULL)
		sceKernelDcacheWritebackInvalidateRange(data, 0x24);
	uint64_t res = kermit_send_wlan_request(KERMIT_INET_SOCKET_IOCTL, 1, (int64_t)sockfd, (uint64_t)command, (uint64_t)data);
	if (data != NULL)
		sceKernelDcacheWritebackInvalidateRange(data, 0x24);
	return extract_result_and_save_errno(res);
}

static void track_module(SceModule2 *mod){
	for (int i = 0;i < sizeof(tracked_modules) / sizeof(tracked_modules[0]);i++){
		if (strcmp(mod->modname, tracked_modules[i].name) == 0){
			LOG("%s: keeping track of %s\n", __func__, tracked_modules[i].name);
			tracked_modules[i].mod = *mod;
			tracked_modules[i].found = true;
			break;
		}
	}
}

int sceKernelQuerySystemCall(void *function);

struct syscall_cache_entry{
	void *function;
	int syscall;
};

// it's not a given that we get to call sceKernelQuerySystemCall in hooks
struct syscall_cache_entry syscall_cache[64] = {0};

static int get_syscall_cached(void *function){
	for(int i = 0;i < sizeof(syscall_cache) / sizeof(syscall_cache[0]);i++){
		if (syscall_cache[i].function == function){
			return syscall_cache[i].syscall;
		}
	}
	int syscall = sceKernelQuerySystemCall(function);
	if (syscall < 0){
		return syscall;
	}
	for(int i = 0;i < sizeof(syscall_cache) / sizeof(syscall_cache[0]);i++){
		if (syscall_cache[i].function == 0){
			syscall_cache[i].function = function;
			syscall_cache[i].syscall = syscall;
			return syscall;
		}
	}
	return syscall;
}

static void replace_import(PspModuleImport *import, uint32_t nid, void *function){
	int syscall = get_syscall_cached(function);
	if (syscall < 0){
		//LOG("%s: bad syscall, fix the export for nid 0x%x\n", __func__, nid);
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
			//LOG("%s: 0x%x 0x%x -> 0x%x 0x%x (0x%x)\n", __func__, orig_instructions[0], orig_instructions[1], addr[0], addr[1], syscall);
			return;
		}
	}
	//LOG("%s: nid 0x%x not found\n", __func__, nid);
}

static void rewrite_mod_import(SceModule2 *mod, const char *libname, uint32_t nid, void* function){
	PspModuleImport *lib = NULL;
	int i = 0;
	while (i < mod->stub_size){
		PspModuleImport *import = (PspModuleImport *)(mod->stub_top + i);
		if (import->name == NULL){
			i += import->entLen * 4;
			continue;
		}
		if (strcmp(import->name, libname) == 0){
			lib = import;
			break;
		}
		i += import->entLen * 4;
	}


	if (lib == NULL){
		//LOG("%s: module %s does not seem to import %s, not patching\n", __func__, mod->modname, libname);
		return;
	}

	replace_import(lib, nid, function);
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
			//LOG("%s: module %s does not seem to import inet, not patching\n", __func__, mod->modname);
			return;
		}

		#define STR(s) #s
		#define REPLACE_FUNCTION(_name, _nid) \
			replace_import(inet_import, _nid, _name##Patched);

			//LOG("%s: replacing %s\n", __func__, STR(_name)); \


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
		REPLACE_FUNCTION(sceNetInetGetPspError, 0x8CA3A97E);

		#undef STR
		#undef REPLACE_FUNCTION

		rewrite_mod_import(mod, "sceNetInet_lib", 0xAEE60F84, sceNetInet_lib_AEE60F84_patched);
}

void rehook_inet_disabled(){
	return;
}

void rehook_inet(){
	//LOG("%s: inet rehook triggered\n", __func__);
	if (game_module_found){
		replace_functions(&game_module);
	}

	for (int i = 0;i < sizeof(tracked_modules) / sizeof(tracked_modules[0]);i++){
		if (!tracked_modules[i].found){
			continue;
		}
		SceKernelModuleInfo info = {0};
		info.size = sizeof(SceKernelModuleInfo);
		uint32_t k1 = pspSdkSetK1(0);
		int query_status = sceKernelQueryModuleInfo(tracked_modules[i].mod.modid, &info);
		pspSdkSetK1(k1);
		if (query_status < 0){
			//LOG("%s: cannot query module info for %s, setting module to not found, 0x%x\n", __func__, tracked_modules[i].name, query_status);
			tracked_modules[i].found = false;
			continue;
		}
		if (strcmp(tracked_modules[i].name, info.name) != 0){
			//LOG("%s: modid 0x%x has name %s instead of %s, setting module to not found\n", __func__, info.name, tracked_modules[i].name);
			tracked_modules[i].found = false;
			continue;
		}
		//LOG("%s: hooking %s\n", __func__, tracked_modules[i].name);
		replace_functions(&tracked_modules[i].mod);
	}
}

static int (*sceUtilityLoadModuleOrig)(int modname) = sceUtilityLoadModule;
int sceUtilityLoadModulePatched(int modname){
	int ret = sceUtilityLoadModuleOrig(modname);
	LOG("%s: loaded module 0x%x, 0x%x\n", __func__, modname, ret);
	if (ret == 0){
		switch(modname){
			case PSP_MODULE_NP_MATCHING2:
				LOG("%s: PSP_MODULE_NP_MATCHING2 loaded, triggering rehook\n", __func__);
				rehook_inet();
				break;
			case PSP_MODULE_NET_HTTP:
				LOG("%s: PSP_MODULE_NET_HTTP loaded, triggering rehook\n", __func__);
				rehook_inet();
				break;
			case PSP_MODULE_NET_SSL:
				LOG("%s: PSP_MODULE_NET_SSL loaded, triggering rehook\n", __func__);
				rehook_inet();
				break;
		}
	}
	return ret;
}

int (*sceUtilityLoadNetModuleOrig)(int modname) = sceUtilityLoadNetModule;
int sceUtilityLoadNetModulePatched(int modname){
	int ret = sceUtilityLoadNetModuleOrig(modname);
	LOG("%s: loaded net module 0x%x, 0x%x\n", __func__, modname, ret);
	if (ret == 0){
		switch(modname){
			case PSP_NET_MODULE_HTTP:
				LOG("%s: PSP_NET_MODULE_HTTP loaded, triggering rehook\n", __func__);
				rehook_inet();
				break;
			case PSP_NET_MODULE_SSL:
				LOG("%s: PSP_NET_MODULE_SSL loaded, triggering rehook\n", __func__);
				rehook_inet();
				break;
		}
	}
	return ret;
}

static void hookUtilityLoadModule(){
	u32 func = sctrlHENFindFunction("sceUtility_Driver", "sceUtility", 0x2A2B3DE0);
	if (func == NULL){
		LOG("%s: sceUtilityLoadModule not found, not hooking\n", __func__);
		return;
	}
	HIJACK_FUNCTION(func, sceUtilityLoadModulePatched, sceUtilityLoadModuleOrig, 0);
}

static void hookUtilityLoadNetModule(){
	u32 func = sctrlHENFindFunction("sceUtility_Driver", "sceUtility", 0x1579a159);
	if (func == NULL){
		LOG("%s: sceUtilityLoadNetModule not found, not hooking\n", __func__);
		return;
	}
	HIJACK_FUNCTION(func, sceUtilityLoadNetModulePatched, sceUtilityLoadNetModuleOrig, 0);
}

int (*sceKernelStartModuleOrig)(SceUID modid, SceSize argsize, void *argp, int *status, SceKernelSMOption *option) = sceKernelStartModule;
int sceKernelStartModulePatched(SceUID modid, SceSize argsize, void *argp, int *status, SceKernelSMOption *option){
	int ret = sceKernelStartModuleOrig(modid, argsize, argp, status, option);
	if (ret < 0){
		return ret;
	}
	SceKernelModuleInfo info = {0};
	info.size = sizeof(SceKernelModuleInfo);
	uint32_t k1 = pspSdkSetK1(0);
	int query_status = sceKernelQueryModuleInfo(modid, &info);
	pspSdkSetK1(k1);
	if (query_status < 0){
		//LOG("%s: failed fetching info for modid %d\n", __func__, modid);
		return ret;
	}
	for (int i = 0;i < sizeof(tracked_modules) / sizeof(tracked_modules[0]);i++){
		if (strcmp(info.name, tracked_modules[i].name) == 0){
			//LOG("%s: %s was started, trigger rehook\n", __func__, tracked_modules[i].name);
			rehook_inet();
			break;
		}
	}
	return ret;
}

static void hookKernelStartModule(){
	u32 func = sctrlHENFindFunction("sceModuleManager", "ModuleMgrForUser", 0x50F0C1EC);
	if (func == NULL){
		LOG("%s: sceKernelStartModule not found, not hooking\n", __func__);
		return;
	}
	HIJACK_FUNCTION(func, sceKernelStartModulePatched, sceKernelStartModuleOrig, 0);
}

int apply_patch(SceModule2 *mod){
	if (mod->text_addr > 0x08800000 && mod->text_addr < 0x08900000 && strcmp("opnssmp", mod->modname) != 0){
		LOG("%s: guessing this is the game, %s, saving module info for later\n", __func__, mod->modname);
		game_module = *mod;
		game_module_found = true;

		// need to fight stargate, OR adrenaline for this one
		int has_stargate = sctrlHENFindFunction("stargate", "stargate", 0x325FE63A) || sctrlHENFindFunction("Stargate", "stargate", 0x325FE63A);

		#if 0
		if (has_stargate){
			// ARK standalone
			hookUtilityLoadModule();
		}else{
			// Adrenaline
			rewrite_mod_import(mod, "sceUtility", 0x2A2B3DE0, sceUtilityLoadModulePatched);
		}
		hookUtilityLoadNetModule();
		#endif
		hookKernelStartModule();

		if (last_handler != NULL){
			return last_handler(mod);
		}
		return 0;
	}

	track_module(mod);

	if (strcmp(mod->modname, "sceNetInet_Library") == 0){
		LOG("%s: inet is being loaded, trigger rehook\n", __func__);
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
