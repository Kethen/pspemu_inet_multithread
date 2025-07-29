#include <vitasdk.h>

#include <psp2/net/net.h>

#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "kermit.h"
#include "error.h"

#include <errno.h>

#define LOG_CMD 0
#define NO_P2P_CRYPT 0

struct inet_worker{
	SceUID sema;
	SceUID mutex;
	struct request_slot *queue[16];
	int num_requests;
	SceUID tid;
	bool should_stop;
	bool busy;
	int id;
};

struct inet_worker workers[1] = {0};
static int num_workers = 0;

// the vita can do up to 1024 sockets?
int32_t sockfd_map[255];
SceUID sockfd_map_mutex = -1;
// usec, same on both sides
int32_t sndtimeo[sizeof(sockfd_map)/sizeof(sockfd_map[0])];
int32_t rcvtimeo[sizeof(sockfd_map)/sizeof(sockfd_map[0])];
bool nbio[sizeof(sockfd_map)/sizeof(sockfd_map[0])];

static void set_timeo(int psp_sockfd, int timeo, bool snd){
	if (psp_sockfd < 0 || psp_sockfd >= sizeof(sndtimeo) / sizeof(sndtimeo[0])){
		return;
	}
	if (snd){
		sndtimeo[psp_sockfd] = timeo;
	}else{
		rcvtimeo[psp_sockfd] = timeo;
	}
}

static int get_timeo(int psp_sockfd, bool snd){
	if (snd){
		return sndtimeo[psp_sockfd];
	}else{
		return rcvtimeo[psp_sockfd];
	}
}

static void set_nbio(int psp_sockfd, bool is_nbio){
	nbio[psp_sockfd] = is_nbio;
}

static bool get_nbio(int psp_sockfd){
	if (psp_sockfd < 0 || psp_sockfd >= sizeof(nbio) / sizeof(nbio[0])){
		return false;
	}
	return nbio[psp_sockfd];
}

static void translate_sockopt(int psp_level, int psp_optname, int *level, int *optname){
	if (psp_level == 0xffff && psp_optname == 0x1009){
		*level = psp_level;
		*optname = SCE_NET_SO_NBIO;
		return;
	}
	*level = psp_level;
	*optname = psp_optname;
}

static void log_request(SceKermitRequest *request){
	LOG("%s: kermit request addr 0x%x\n", __func__, request);
	switch(request->cmd){
		// socket number all have an offset
		// 0xabd54000? 0x0bd54000 might be a kermit magic address on the psp side, it keeps being used and I don't see real addresses; might end up needing a psp side plugin as well
		case 0x40:{
			LOG("%s: socket 0x%x 0x%x 0x%x\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[1], (uint32_t)request->args[2]);
			return;
		}
		case 0x4b:{
			// rearranged!
			LOG("%s: bind %d 0x%x %d\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[2], (uint32_t)request->args[1]);
			return;
		}
		case 0x3b:{
			LOG("%s: listen %d %d\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[1]);
			return;
		}
		case 0x3c:{
			// sockfd, address, size
			// size and address buffer were merged!
			LOG("%s: accept %d 0x%x 0x%x\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[2], (uint32_t)request->args[1]);
			return;
		}
		case 0x47:{
			// sockfd, magic address, size
			// address size and address was reversed!
			LOG("%s: connect %d 0x%x %d\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[2], (uint32_t)request->args[1]);
			return;
		}
		case 0x44:{
			// sockfd, level, name, magic address, opt size
			// opt size and pointer was reversed!
			LOG("%s: setsockopt %d 0x%x 0x%x 0x%x %d\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[1], (uint32_t)request->args[2], (uint32_t)request->args[4], (uint32_t)request->args[3]);
			return;
		}
		case 0x31:{
			// sockfd, level, name, magic address, opt size
			// opt size and pointer was reversed!
			LOG("%s: getsockopt %d 0x%x 0x%x 0x%x 0x%x\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[1], (uint32_t)request->args[2], (uint32_t)request->args[4], (uint32_t)request->args[3]);
			return;
		}
		case 0x32:{
			// sockfd, magics address, address size
			LOG("%s: getsockname %d 0x%x 0x%x\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[2], (uint32_t)request->args[1]);
			return;
		}
		case 0x35:{
			// sockfd, magic address, address size
			LOG("%s: getpeername %d 0x%x 0x%x\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[2], (uint32_t)request->args[1]);
			return;
		}
		case 0x36:{
			LOG("%s: send/sendto %d 0x%x %d 0x%x 0x%x %d\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[1], (uint32_t)request->args[2], (uint32_t)request->args[3], (uint32_t)request->args[4], (uint32_t)request->args[5]);
			return;
		}
		case 0x39:{
			LOG("%s: recv/recvfrom %d 0x%x %d 0x%x 0x%x 0x%x\n", __func__, (uint32_t)request->args[0], (uint32_t)request->args[1], (uint32_t)request->args[2], (uint32_t)request->args[3], (uint32_t)request->args[4], (uint32_t)request->args[5]);
			return;
		}
		case 0x41:{
			LOG("%s: close %d\n", __func__, (uint32_t)request->args[0]);
			return;
		}
		case 0x45:{
			LOG("%s: get mac address 0x%x\n", __func__, (uint32_t)request->args[0]);
			return;
		}
	}

	char args[256];
	int offset = 0;
	for (int i = 0;i < 14;i++){
		offset += sprintf(&args[offset], "0x%x ", *(uint32_t*)&request->args[i]);
	}

	LOG("%s: unknown 0x%x %s\n", __func__, request->cmd, args);
}

struct psp_poll_fd{
	int sockfd;
	int16_t events;
	int16_t revents;
};

enum psp_poll_events{
	POLLIN = 0x0001,
	POLLPRI = 0x0002,
	POLLOUT = 0x0004,
	POLLRDNORM = 0x0040,
	POLLRDBAND = 0x0080,
	POLLWRBAND = 0x0100,

	POLLERR = 0x0008,
	POLLHUP = 0x0010,
	POLLNVAL = 0x0020,
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

static int32_t get_sockfd(int psp_sockfd){
	if (psp_sockfd < 0 || psp_sockfd >= sizeof(sockfd_map) / sizeof(int32_t)){
		return -1;
	}
	sceKernelLockMutex(sockfd_map_mutex, 1, 0);
	int sockfd = sockfd_map[psp_sockfd];
	sceKernelUnlockMutex(sockfd_map_mutex, 1);
	return sockfd;
}

static int32_t map_sockfd(int sockfd){
	//sceKernelLockMutex(sockfd_map_mutex, 1, 0);
	// https://xkcd.com/3062/ let's... skip sock 0
	for (int i = 1;i < sizeof(sockfd_map) / sizeof(int32_t);i++){
		if (sockfd_map[i] == -1){
			sockfd_map[i] = sockfd;
			//sceKernelUnlockMutex(sockfd_map_mutex, 1);
			return i;
		}
	}
	//sceKernelUnlockMutex(sockfd_map_mutex, 1);
	return -1;
}

static void remove_sockfd(int psp_sockfd){
	if (psp_sockfd < 0){
		return;
	}
	if (psp_sockfd >= sizeof(sockfd_map) / sizeof(int32_t)){
		return;
	}
	//sceKernelLockMutex(sockfd_map_mutex, 1, 0);
	sockfd_map[psp_sockfd] = -1;
	//sceKernelUnlockMutex(sockfd_map_mutex, 1);
}

struct psp_select_timeval{
	uint32_t tv_sec;
	uint32_t tv_usec;
};

int (*sceNetSyscallIoctl_import)(int sockfd, uint32_t command, void *data) = NULL;

static bool handle_request(struct request_slot *request, struct inet_worker *worker){
	int32_t response[2] = {0};
	bool request_done = false;

	if (request->op_begin == 0){
		request->op_begin = sceKernelGetSystemTimeWide();
	}

	switch(request->cmd){
		case KERMIT_INET_SOCKET:{
			int32_t type = *(int32_t*)&request->args[1];
			int sockfd = sceNetSocket("pspemu_inet_multithread", SCE_NET_AF_INET, type, 0);
			if (sockfd < 0){
				#if LOG_CMD
				LOG("%s: socket 0x%x, 0x%x\n", __func__, type, sockfd);
				#endif
				response[1] = sockfd;
				request_done = true;
				break;
			}
			int psp_sockfd = map_sockfd(sockfd);
			if (psp_sockfd == -1){
				sceNetSocketClose(sockfd);
				response[1] = -1;
				response[0] = ENOMEM;
				request_done = true;
				#if LOG_CMD
				LOG("%s: socket 0x%x failed mapping psp socket during socket creation\n", __func__, type);
				#endif
				break;
			}
			response[1] = psp_sockfd;
			request_done = true;
			set_timeo(psp_sockfd, 0, true);
			set_timeo(psp_sockfd, 0, false);
			set_nbio(psp_sockfd, false);
			int opt = 1;
			sceNetSetsockopt(sockfd, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &opt, sizeof(opt));
			#if LOG_CMD
			LOG("%s: socket 0x%x, 0x%x/0x%x\n", __func__, type, sockfd, psp_sockfd);
			#endif

			break;
		}
		case KERMIT_INET_BIND:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
			SceNetSockaddrIn addr = {0};
			addr.sin_len = sizeof(addr);
			addr.sin_family = SCE_NET_AF_INET;
			addr.sin_port = psp_addr->sin_port;
			addr.sin_vport = psp_addr->sin_vport;
			addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
			response[1] = sceNetBind(sockfd, (void *)&addr, sizeof(SceNetSockaddrIn));
			request_done = true;
			#if LOG_CMD
			LOG("%s: bind 0x%x/0x%x 0x%x %d (%d), 0x%x\n", __func__, sockfd, psp_sockfd, addr.sin_addr.s_addr, sceNetNtohs(addr.sin_port), sceNetNtohs(addr.sin_vport), response[1]);
			#endif

			break;
		}
		case KERMIT_INET_LISTEN:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t backlog = *(int32_t *)&request->args[1];
			response[1] = sceNetListen(sockfd, backlog);
			request_done = true;

			break;
		}
		case KERMIT_INET_ACCEPT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetSockaddrIn *addr_out = request->args[1] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, sizeof(SceNetSockaddrIn));
			int32_t *addrlen_in_out = request->args[2] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			int accept_sockfd = sceNetAccept(sockfd, (void *)addr_out, addrlen_in_out);

			if (*(uint32_t*)&accept_sockfd == SCE_NET_ERROR_EAGAIN){
				if (!get_nbio(psp_sockfd)){
					// just try again later
					break;
				}
				// let the other side know that we have no incoming connection
				response[1] = -1;
				response[0] = EAGAIN;
				request_done = true;
				break;
			}

			if (accept_sockfd < 0){
				response[1] = accept_sockfd;
				request_done = true;
				break;
			}

			int psp_accept_sockfd = map_sockfd(accept_sockfd);
			if (psp_accept_sockfd == -1){
				sceNetSocketClose(accept_sockfd);
				response[1] = -1;
				response[0] = ENOMEM;
				request_done = true;
				break;
			}

			response[1] = psp_accept_sockfd;
			request_done = true;
			if (addr_out != NULL)
				kermit_pspemu_writeback_cache(addr_out, sizeof(SceNetSockaddrIn));
			if (addrlen_in_out != NULL)
				kermit_pspemu_writeback_cache(addrlen_in_out, sizeof(int32_t));

			#if LOG_CMD
			LOG("%s: accept 0x%x/0x%x -> 0x%x/0x%x from 0x%x %d (%d)\n", __func__, sockfd, psp_sockfd, accept_sockfd, psp_accept_sockfd, addr_out->sin_addr.s_addr, sceNetNtohs(addr_out->sin_port), sceNetNtohs(addr_out->sin_vport));
			#endif

			break;
		}
		case KERMIT_INET_CONNECT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
			SceNetSockaddrIn addr = {0};
			addr.sin_len = sizeof(addr);
			addr.sin_family = SCE_NET_AF_INET;
			addr.sin_port = psp_addr->sin_port;
			addr.sin_vport = psp_addr->sin_vport;
			addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
			int32_t addrlen = *(int32_t*)&request->args[2];

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			if (!request->in_progress){
				response[1] = sceNetConnect(sockfd, (void *)&addr, addrlen);
				#if LOG_CMD
				LOG("%s: connect initial 0x%x/0x%x 0x%x %d (%d), 0x%x\n", __func__, sockfd, psp_sockfd, addr.sin_addr.s_addr, sceNetNtohs(addr.sin_port), sceNetNtohs(addr.sin_vport), response[1]);
				#endif
				if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EINPROGRESS){
					if (!get_nbio(psp_sockfd)){
						// come back to this later
						request->in_progress = 1;
						break;
					}
					// the other side is also nbio
					response[1] = -1;
					response[0] = EINPROGRESS;
				}
			}else{
				// back from the last cycle
				int epollfd = sceNetEpollCreate("pspemu_inet_multithread connect", 0);
				if (epollfd < 0){
					// I guess we just try again later?
					LOG("%s: failed creating epoll fd for blocked connect, 0x%x\n", __func__, epollfd);
					break;
				}
				SceNetEpollEvent event = {0};
				event.events |= SCE_NET_EPOLLOUT;
				sceNetEpollControl(epollfd, SCE_NET_EPOLL_CTL_ADD, sockfd, &event);
				int events = sceNetEpollWait(epollfd, &event, 1, 0);
				if (events < 0){
					// just try again
					LOG("%s: epoll wait failed, 0x%x\n", __func__, events);
					sceNetEpollDestroy(epollfd);
					break;
				}
				if (events == 0){
					// no event, try again
					sceNetEpollDestroy(epollfd);
					break;
				}
				if (events == 1){
					if (!(event.events & SCE_NET_EPOLLOUT)){
						// other events, try again
						sceNetEpollDestroy(epollfd);
						break;
					}

					// connect has finished
					uint32_t error = 0;
					int optlen = sizeof(error);
					int get_status = sceNetGetsockopt(sockfd, SCE_NET_SOL_SOCKET, SCE_NET_SO_ERROR, &error, &optlen);
					if (get_status < 0){
						LOG("%s: failed getting socket option after connect, 0x%x\n", __func__, get_status);
						error = get_status;
					}else if (error != 0){
						error |= 0x80410100;
					}
					*(uint32_t*)&response[1] = error;
					sceNetEpollDestroy(epollfd);
				}
			}
			request_done = true;

			#if LOG_CMD
			LOG("%s: connect 0x%x/0x%x 0x%x %d (%d), 0x%x\n", __func__, sockfd, psp_sockfd, addr.sin_addr.s_addr, sceNetNtohs(addr.sin_port), sceNetNtohs(addr.sin_vport), response[1]);
			#endif

			break;
		}
		case KERMIT_INET_SETSOCKOPT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t psp_level = *(int32_t *)&request->args[1];
			int32_t psp_optname = *(int32_t *)&request->args[2];
			int32_t level = 0;
			int32_t optname = 0;
			translate_sockopt(psp_level, psp_optname, &level, &optname);
			int32_t optlen = *(int32_t *)&request->args[4];
			void *optval = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[3], KERMIT_ADDR_MODE_IN, optlen);

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			#if NO_P2P_CRYPT
			if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_USECRYPTO){
				LOG("%s: blocked setting SCE_NET_SO_USECRYPTO\n", __func__);
				response[1] = 0;
				request_done = true;
				break;
			}

			if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_USESIGNATURE){
				LOG("%s: blocked setting SCE_NET_SO_USESIGNATURE\n", __func__);
				response[1] = 0;
				request_done = true;
				break;
			}
			#endif

			// we handle these options
			if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_SNDTIMEO){
				set_timeo(psp_sockfd, *(int32_t*)optval, true);
				response[1] = 0;
				request_done = true;
				#if LOG_CMD
				LOG("%s: setsockopt 0x%x/0x%x 0x%x/0x%x 0x%x/0x%x %d %d, builtin\n", __func__, sockfd, psp_sockfd, level, psp_level, optname, psp_optname, *(int32_t*)optval, optlen);
				#endif
				break;
			}else if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_RCVTIMEO){
				set_timeo(psp_sockfd, *(int32_t*)optval, false);
				response[1] = 0;
				request_done = true;
				#if LOG_CMD
				LOG("%s: setsockopt 0x%x/0x%x 0x%x/0x%x 0x%x/0x%x %d %d, builtin\n", __func__, sockfd, psp_sockfd, level, psp_level, optname, psp_optname, *(int32_t*)optval, optlen);
				#endif
				break;
			}else if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_NBIO){
				set_nbio(psp_sockfd, *(int32_t*)optval ? true : false);
				response[1] = 0;
				request_done = true;
				#if LOG_CMD
				LOG("%s: setsockopt 0x%x/0x%x 0x%x/0x%x 0x%x/0x%x %d %d, builtin\n", __func__, sockfd, psp_sockfd, level, psp_level, optname, psp_optname, *(int32_t*)optval, optlen);
				#endif
				break;
			}

			response[1] = sceNetSetsockopt(sockfd, level, optname, optval, optlen);
			request_done = true;

			#if LOG_CMD
			int32_t optval_log = 0;
			if (optlen == 1){
				optval_log = *(int8_t*)optval;
			}
			if (optlen == 2){
				optval_log = *(int16_t*)optval;
			}
			optval_log = *(int32_t*)optval;
			LOG("%s: setsockopt 0x%x/0x%x 0x%x/0x%x 0x%x/0x%x %d %d, 0x%x\n", __func__, sockfd, psp_sockfd, level, psp_level, optname, psp_optname, optval_log, optlen, response[1]);
			#endif

			break;
		}
		case KERMIT_INET_GETSOCKOPT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t psp_level = *(int32_t *)&request->args[1];
			int32_t psp_optname = *(int32_t *)&request->args[2];
			int32_t level = 0;
			int32_t optname = 0;
			translate_sockopt(psp_level, psp_optname, &level, &optname);
			int32_t *optlen_in_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[4], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			void *optval_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[3], KERMIT_ADDR_MODE_OUT, *optlen_in_out);

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			// we handle these options
			if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_SNDTIMEO){
				*(int32_t*)optval_out = get_timeo(psp_sockfd, true);
				response[1] = 0;
			}else if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_RCVTIMEO){
				*(int32_t*)optval_out = get_timeo(psp_sockfd, false);
				response[1] = 0;
			}else if (level == SCE_NET_SOL_SOCKET && optname == SCE_NET_SO_NBIO){
				*(int32_t*)optval_out = get_nbio(psp_sockfd) ? 1 : 0;
				response[1] = 0;
			}else{
				response[1] = sceNetGetsockopt(sockfd, level, optname, optval_out, optlen_in_out);
			}
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(optlen_in_out, sizeof(int32_t));
				kermit_pspemu_writeback_cache(optval_out, *optlen_in_out);
			}
			request_done = true;

			#if LOG_CMD
			int32_t optval_log = 0;
			if (*optlen_in_out == 1){
				optval_log = *(int8_t*)optval_out;
			}
			if (*optlen_in_out == 2){
				optval_log = *(int16_t*)optval_out;
			}
			optval_log = *(int32_t*)optval_out;
			LOG("%s: getsockopt 0x%x/0x%x 0x%x/0x%x 0x%x/0x%x %d %d, 0x%x\n", __func__, sockfd, psp_sockfd, level, psp_level, optname, psp_optname, optval_log, *optlen_in_out, response[1]);
			#endif

			break;
		}
		case KERMIT_INET_GETSOCKNAME:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t *addrlen_in_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			SceNetSockaddrIn *addr_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, *addrlen_in_out);
			response[1] = sceNetGetsockname(sockfd, (void *)addr_out, addrlen_in_out);
			request_done = true;
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(addr_out, *addrlen_in_out);
				kermit_pspemu_writeback_cache(addrlen_in_out, sizeof(uint32_t));
			}

			break;
		}
		case KERMIT_INET_GETPEERNAME:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t *addrlen_in_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			SceNetSockaddrIn *addr_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, *addrlen_in_out);
			response[1] = sceNetGetpeername(sockfd, (void *)addr_out, addrlen_in_out);
			request_done = true;
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(addr_out, *addrlen_in_out);
				kermit_pspemu_writeback_cache(addrlen_in_out, sizeof(uint32_t));
			}

			break;
		}
		case KERMIT_INET_SEND:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t *)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, size);
			int32_t flags = *(int32_t *)&request->args[3];
			#if NO_P2P_CRYPT
			flags = flags & (~SCE_NET_MSG_USECRYPTO);
			flags = flags & (~SCE_NET_MSG_USESIGNATURE);
			#endif

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			response[1] = sceNetSend(sockfd, buf, size, flags);

			#if LOG_CMD
			LOG("%s: send 0x%x/0x%x 0x%x %u 0x%x, 0x%x\n", __func__, sockfd, psp_sockfd, buf, size, flags, response[1]);
			#endif

			if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EAGAIN){
				int timeout = get_timeo(psp_sockfd, true);
				bool timedout = timeout != 0 && sceKernelGetSystemTimeWide() - request->op_begin > timeout;
				if (!get_nbio(psp_sockfd) && !(flags & SCE_NET_MSG_DONTWAIT) && !timedout){
					// try again later
					break;
				}
				response[1] = -1;
				response[0] = EAGAIN;
			}
			request_done = true;

			break;
		}
		case KERMIT_INET_SENDTO:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t *)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, size);
			int32_t flags = *(int32_t *)&request->args[3];
			#if NO_P2P_CRYPT
			flags = flags & (~SCE_NET_MSG_USECRYPTO);
			flags = flags & (~SCE_NET_MSG_USESIGNATURE);
			#endif

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[4], KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
			SceNetSockaddrIn addr = {0};
			addr.sin_len = sizeof(addr);
			addr.sin_family = SCE_NET_AF_INET;
			addr.sin_port = psp_addr->sin_port;
			addr.sin_vport = psp_addr->sin_vport;
			addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
			response[1] = sceNetSendto(sockfd, buf, size, flags, (void *)&addr, sizeof(SceNetSockaddrIn));

			#if LOG_CMD
			LOG("%s: sendto 0x%x/0x%x 0x%x %u 0x%x 0x%x %d (%d), 0x%x\n", __func__, sockfd, psp_sockfd, buf, size, flags, addr.sin_addr.s_addr, sceNetNtohs(addr.sin_port), sceNetNtohs(addr.sin_vport), response[1]);
			#endif

			if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EAGAIN){
				int timeout = get_timeo(psp_sockfd, true);
				bool timedout = timeout != 0 && sceKernelGetSystemTimeWide() - request->op_begin > timeout;
				if (!get_nbio(psp_sockfd) && !(flags & SCE_NET_MSG_DONTWAIT) && !timedout){
					// try again later
					break;
				}
				response[1] = -1;
				response[0] = EAGAIN;
			}
			request_done = true;

			break;
		}
		case KERMIT_INET_SENDMSG:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetMsghdr *psp_msg = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, sizeof(SceNetMsghdr));
			SceNetMsghdr msg = {0};
			SceNetSockaddrIn addr = {0};
			if (psp_msg->msg_name != NULL && psp_msg->msg_namelen != 0){
				SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr((uint32_t)psp_msg->msg_name, KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
				addr.sin_len = sizeof(addr);
				addr.sin_family = SCE_NET_AF_INET;
				addr.sin_port = psp_addr->sin_port;
				addr.sin_vport = psp_addr->sin_vport;
				addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
				msg.msg_name = &addr;
				msg.msg_namelen = sizeof(SceNetSockaddrIn);
			}
			msg.msg_iovlen = psp_msg->msg_iovlen;
			SceNetIovec msg_iov[64];
			if (psp_msg->msg_iov != NULL && psp_msg->msg_iovlen != 0){
				SceNetIovec *psp_msg_iov = kermit_get_pspemu_addr_from_psp_addr((uint32_t)psp_msg->msg_iov, KERMIT_ADDR_MODE_IN, psp_msg->msg_iovlen * sizeof(SceNetIovec));

				// this could be problematic if we run out of stack
				msg.msg_iov = msg_iov;
				if (psp_msg->msg_iovlen > sizeof(msg_iov) / sizeof(SceNetIovec)){
					// uhhhhhhhhhh
					LOG("%s: cannot handle giant sendmsg with %d chunks\n", __func__, psp_msg->msg_iovlen);
					response[1] = -1;
					response[0] = ENOMEM;
					break;
				}
				for (int i = 0;i < msg.msg_iovlen;i++){
					msg_iov[i].iov_len = psp_msg_iov[i].iov_len;
					msg_iov[i].iov_base = kermit_get_pspemu_addr_from_psp_addr((uint32_t)psp_msg_iov[i].iov_base, KERMIT_ADDR_MODE_IN, msg_iov[i].iov_len);
				}
			}
			// ignore msg_control for now
			int32_t flags = *(int32_t *)&request->args[2];
			#if NO_P2P_CRYPT
			flags = flags & (~SCE_NET_MSG_USECRYPTO);
			flags = flags & (~SCE_NET_MSG_USESIGNATURE);
			#endif

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			response[1] = sceNetSendmsg(sockfd, &msg, flags);

			#if LOG_CMD
			LOG("%s: sendmsg 0x%x/0x%x 0x%x/0x%x 0x%x, 0x%x\n", __func__, sockfd, psp_sockfd, &msg, psp_msg, flags, response[1]);
			#endif

			if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EAGAIN){
				int timeout = get_timeo(psp_sockfd, true);
				bool timedout = timeout != 0 && sceKernelGetSystemTimeWide() - request->op_begin > timeout;
				if (!get_nbio(psp_sockfd) && !(flags & SCE_NET_MSG_DONTWAIT) && !timedout){
					// try again later
					break;
				}
				response[1] = -1;
				response[0] = EAGAIN;
			}
			request_done = true;

			break;
		}
		case KERMIT_INET_RECV:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t*)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, size);
			int32_t flags = *(int32_t *)&request->args[3];
			#if NO_P2P_CRYPT
			flags = flags & (~SCE_NET_MSG_USECRYPTO);
			flags = flags & (~SCE_NET_MSG_USESIGNATURE);
			#endif

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			response[1] = sceNetRecv(sockfd, buf, size, flags);
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(buf, size);
			}

			#if LOG_CMD
			LOG("%s: recv 0x%x/0x%x 0x%x %u 0x%x, 0x%x\n", __func__, sockfd, psp_sockfd, buf, size, flags, response[1]);
			#endif

			if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EAGAIN){
				int timeout = get_timeo(psp_sockfd, false);
				bool timedout = timeout != 0 && sceKernelGetSystemTimeWide() - request->op_begin > timeout;
				if (!get_nbio(psp_sockfd) && !(flags & SCE_NET_MSG_DONTWAIT) && !timedout){
					// try again later
					break;
				}
				response[1] = -1;
				response[0] = EAGAIN;
			}
			request_done = true;

			break;
		}
		case KERMIT_INET_RECVFROM:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t*)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, size);
			int32_t flags = *(int32_t *)&request->args[3];
			#if NO_P2P_CRYPT
			flags = flags & (~SCE_NET_MSG_USECRYPTO);
			flags = flags & (~SCE_NET_MSG_USESIGNATURE);
			#endif
			int32_t *addrlen_in_out = request->args[5] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[5], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			SceNetSockaddrIn *addr_out = request->args[4] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[4], KERMIT_ADDR_MODE_OUT, *addrlen_in_out);

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			response[1] = sceNetRecvfrom(sockfd, buf, size, flags, (void *)addr_out, addrlen_in_out);
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(buf, size);
				if (addrlen_in_out != NULL)
					kermit_pspemu_writeback_cache(addrlen_in_out, sizeof(int32_t));
				if (addrlen_in_out != NULL && addr_out != NULL)
					kermit_pspemu_writeback_cache(addr_out, *addrlen_in_out);
			}

			#if LOG_CMD
			LOG("%s: recvfrom 0x%x/0x%x 0x%x %u 0x%x 0x%x %d (%d), 0x%x\n", __func__, sockfd, psp_sockfd, buf, size, flags, addr_out == NULL ? -1 : addr_out->sin_addr.s_addr, addr_out == NULL ? -1 : sceNetNtohs(addr_out->sin_port), addr_out == NULL ? -1 : sceNetNtohs(addr_out->sin_vport), response[1]);
			#endif

			if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EAGAIN){
				int timeout = get_timeo(psp_sockfd, false);
				bool timedout = timeout != 0 && sceKernelGetSystemTimeWide() - request->op_begin > timeout;
				if (!get_nbio(psp_sockfd) && !(flags & SCE_NET_MSG_DONTWAIT) && !timedout){
					// try again later
					break;
				}
				response[1] = -1;
				response[0] = EAGAIN;
			}
			request_done = true;

			break;
		}
		case KERMIT_INET_RECVMSG:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetMsghdr *psp_msg = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, sizeof(SceNetMsghdr));
			SceNetMsghdr msg = {0};
			msg.msg_namelen = psp_msg->msg_namelen;
			if (psp_msg->msg_name != NULL && psp_msg->msg_namelen != 0){
				msg.msg_name = kermit_get_pspemu_addr_from_psp_addr((uint32_t)psp_msg->msg_name, KERMIT_ADDR_MODE_OUT, psp_msg->msg_namelen);
			}
			msg.msg_iovlen = psp_msg->msg_iovlen;
			SceNetIovec msg_iov[64];
			if (psp_msg->msg_iov != NULL && psp_msg->msg_iovlen != 0){
				SceNetIovec *psp_msg_iov = kermit_get_pspemu_addr_from_psp_addr((uint32_t)psp_msg->msg_iov, KERMIT_ADDR_MODE_IN, psp_msg->msg_iovlen * sizeof(SceNetIovec));

				// this could be problematic if we run out of stack
				msg.msg_iov = msg_iov;
				if (psp_msg->msg_iovlen > sizeof(msg_iov) / sizeof(SceNetIovec)){
					// uhhhhhhhhhh
					LOG("%s: cannot handle giant recvmsg with %d chunks\n", __func__, psp_msg->msg_iovlen);
					response[1] = -1;
					response[0] = ENOMEM;
					break;
				}
				for (int i = 0;i < msg.msg_iovlen;i++){
					msg_iov[i].iov_len = psp_msg_iov[i].iov_len;
					msg_iov[i].iov_base = kermit_get_pspemu_addr_from_psp_addr((uint32_t)psp_msg_iov[i].iov_base, KERMIT_ADDR_MODE_OUT, msg_iov[i].iov_len);
				}
			}
			// ignore msg_control for now
			int32_t flags = *(int32_t *)&request->args[2];
			#if NO_P2P_CRYPT
			flags = flags & (~SCE_NET_MSG_USECRYPTO);
			flags = flags & (~SCE_NET_MSG_USESIGNATURE);
			#endif

			if (sockfd == -1){
				response[1] = -1;
				response[0] = EBADF;
				request_done = true;
				break;
			}

			response[1] = sceNetRecvmsg(sockfd, &msg, flags);
			if (response[1] >= 0){
				if (psp_msg->msg_name != NULL && psp_msg->msg_namelen != 0){
					kermit_pspemu_writeback_cache(msg.msg_name, msg.msg_namelen);
				}
				if (msg.msg_iov != NULL && msg.msg_iovlen != 0){
					for (int i = 0;i < msg.msg_iovlen;i++){
						kermit_pspemu_writeback_cache(msg_iov[i].iov_base, msg_iov[i].iov_len);
					}
				}
			}

			#if LOG_CMD
			LOG("%s: recvmsg 0x%x/0x%x 0x%x/0x%x 0x%x, 0x%x\n", __func__, sockfd, psp_sockfd, &msg, psp_msg, flags, response[1]);
			#endif

			if (*(uint32_t*)&response[1] == SCE_NET_ERROR_EAGAIN){
				int timeout = get_timeo(psp_sockfd, false);
				bool timedout = timeout != 0 && sceKernelGetSystemTimeWide() - request->op_begin > timeout;
				if (!get_nbio(psp_sockfd) && !(flags & SCE_NET_MSG_DONTWAIT) && !timedout){
					// try again later
					break;
				}
				response[1] = -1;
				response[0] = EAGAIN;
			}
			request_done = true;

			break;
		}
		case KERMIT_INET_CLOSE_WITH_RST:
		case KERMIT_INET_CLOSE:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			response[1] = sceNetSocketClose(sockfd);
            request_done = true;
			if (response[1] >= 0){
				#if LOG_CMD
				LOG("%s: removed socket 0x%x/0x%x\n", __func__, sockfd, psp_sockfd);
				#endif
				remove_sockfd(psp_sockfd);
			}

			break;
		}
		case KERMIT_INET_POLL:{
			int32_t nfds = *(int32_t*)&request->args[1];
			struct psp_poll_fd *fds = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[0], KERMIT_ADDR_MODE_INOUT, nfds * sizeof(struct psp_poll_fd));
			int32_t timeout = *(int32_t*)&request->args[2];

			SceNetEpollEvent events[255] = {0};

			if (nfds > sizeof(events) / sizeof(SceNetEpollEvent)){
				LOG("%s: too many fds on poll, %d\n", __func__, nfds);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}

			if (timeout < -1){
				response[1] = -1;
				response[0] = EINVAL;
				break;
			}

			int epollfd = sceNetEpollCreate("pspemu_inet_multithread poll", 0);
			if (epollfd < 0){
				LOG("%s: failed creating epoll instance for poll, 0x%x\n", __func__, epollfd);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}

			#if LOG_CMD
			int poll_in_log_offset = 0;
			char poll_in_log[1024 * 2] = {0};
			int poll_out_log_offset = 0;
			char poll_out_log[1024 * 2] = {0};
			int poll_in_rlog_offset = 0;
			char poll_in_rlog[1024 * 2] = {0};
			int poll_out_rlog_offset = 0;
			char poll_out_rlog[1024 * 2] = {0};
			#endif

			int epoll_fds = 0;
			bool has_event = false;
			for (int i = 0;i < nfds;i++){
				SceNetEpollEvent event = {0};

				// only do these for now, since they map correctly to epoll
				if (fds[i].events & POLLIN || fds[i].events & POLLRDNORM){
					event.events |= SCE_NET_EPOLLIN;
				}
				if (fds[i].events & POLLOUT){
					event.events |= SCE_NET_EPOLLOUT;
				}

				if (event.events == 0){
					continue;
				}

				int sockfd = get_sockfd(fds[i].sockfd);
				if (sockfd == -1){
					fds[i].revents |= POLLNVAL;
					has_event = true;
					continue;
				}

				#if LOG_CMD
				if (event.events & SCE_NET_EPOLLIN){
					poll_in_log_offset += sprintf(&poll_in_log[poll_in_log_offset], "0x%x ", fds[i].sockfd);
				}
				if (event.events & SCE_NET_EPOLLOUT){
					poll_out_log_offset += sprintf(&poll_out_log[poll_out_log_offset], "0x%x ", fds[i].sockfd);
				}
				#endif

				event.data.fd = i;

				sceNetEpollControl(epollfd, SCE_NET_EPOLL_CTL_ADD, sockfd, &event);
				epoll_fds++;
			}

			uint32_t timeout_usec = timeout * 1000;

			if (epoll_fds == 0){
				sceNetEpollDestroy(epollfd);
				response[1] = 0;
				if (sceKernelGetSystemTimeWide() - request->op_begin < timeout_usec){
					// try again
					break;
				}
				request_done = true;
				break;
			}

			response[1] = sceNetEpollWait(epollfd, events, sizeof(events) / sizeof(SceNetEpollEvent), 0);
			sceNetEpollDestroy(epollfd);

			if (response[1] < 0){
				request_done = true;
				break;
			}

			for (int i = 0;i < response[1];i++){
				if (events[i].events & SCE_NET_EPOLLIN){
					fds[events[i].data.fd].revents |= POLLIN | POLLRDNORM;
					#if LOG_CMD
					poll_in_rlog_offset += sprintf(&poll_in_rlog[poll_in_rlog_offset], "0x%x ", fds[events[i].data.fd].sockfd);
					#endif
					has_event = true;
				}
				if (events[i].events & SCE_NET_EPOLLOUT){
					fds[events[i].data.fd].revents |= POLLOUT;
					#if LOG_CMD
					poll_out_rlog_offset += sprintf(&poll_out_rlog[poll_out_rlog_offset], "0x%x ", fds[events[i].data.fd].sockfd);
					#endif
					has_event = true;
				}
				if (events[i].events & SCE_NET_EPOLLERR){
					fds[events[i].data.fd].revents |= POLLERR;
					has_event = true;
				}
				if (events[i].events & SCE_NET_EPOLLHUP){
					fds[events[i].data.fd].revents |= POLLHUP;
					has_event = true;
				}
			}

			if (!has_event){
				if (sceKernelGetSystemTimeWide() - request->op_begin < timeout_usec){
					// wait for next time
					break;
				}
			}
			request_done = true;

			kermit_pspemu_writeback_cache(fds, nfds * sizeof(struct psp_poll_fd));

			#if LOG_CMD
			LOG("%s: poll 0x%x(%s)(%s)(%s)(%s) %d %d, 0x%x\n", __func__, fds, poll_in_log, poll_out_log, poll_in_rlog, poll_out_rlog, nfds, timeout, response[1]);
			#endif

			break;
		}
		case KERMIT_INET_SELECT:{
			int32_t nfds = *(int32_t *)&request->args[0];
			uint32_t *readfds = *(uint32_t*)&request->args[1] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[1], KERMIT_ADDR_MODE_INOUT, sizeof(uint32_t) * 8);
			uint32_t *writefds = *(uint32_t*)&request->args[2] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(uint32_t) * 8);
			uint32_t *exceptfds = *(uint32_t*)&request->args[3] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[3], KERMIT_ADDR_MODE_INOUT, sizeof(uint32_t) * 8);
			struct psp_select_timeval *timeout = *(uint32_t*)&request->args[4] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[4], KERMIT_ADDR_MODE_IN, sizeof(struct psp_select_timeval));

			SceNetEpollEvent events[255] = {0};

			if (nfds > sizeof(events) / sizeof(SceNetEpollEvent) + 1 || nfds < 1){
				LOG("%s: too many fds on select, %d\n", __func__, nfds);
				response[1] = -1;
				response[0] = EINVAL;
				break;
			}

			int epollfd = sceNetEpollCreate("pspemu_inet_multithread select", 0);
			if (epollfd < 0){
				LOG("%s: failed creating epoll instance for select, 0x%x\n", __func__, epollfd);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}

			#if LOG_CMD
			int readfds_log_offset = 0;
			char readfds_log[1024 * 2] = {0};
			int writefds_log_offset = 0;
			char writefds_log[1024 * 2] = {0};
			int readfds_out_log_offset = 0;
			char readfds_out_log[1024 * 2] = {0};
			int writefds_out_log_offset = 0;
			char writefds_out_log[1024 * 2] = {0};
			#endif

			int epoll_fds = 0;
			for (int i = 0;i < nfds;i++){
				SceNetEpollEvent event = {0};

				int sockfd = get_sockfd(i);

				// only do these for now, since they map correctly to epoll
				if (readfds != NULL && psp_select_fd_is_set(readfds, i)){
					event.events |= SCE_NET_EPOLLIN;
				}
				if (writefds != NULL && psp_select_fd_is_set(writefds, i)){
					event.events |= SCE_NET_EPOLLOUT;
				}

				if (event.events == 0){
					continue;
				}

				if (sockfd == -1){
					response[1] = -1;
					response[0] = EBADF;
					request_done = true;
					break;
				}

				#if LOG_CMD
				if (event.events & SCE_NET_EPOLLIN){
					readfds_log_offset += sprintf(&readfds_log[readfds_log_offset], "0x%x ", i);
				}
				if (event.events & SCE_NET_EPOLLOUT){
					writefds_log_offset += sprintf(&writefds_log[writefds_log_offset], "0x%x ", i);
				}
				#endif

				event.data.fd = i;

				sceNetEpollControl(epollfd, SCE_NET_EPOLL_CTL_ADD, sockfd, &event);
				epoll_fds++;
			}

			uint32_t timeout_usec = 0;
			if (timeout != NULL){
				timeout_usec = timeout->tv_usec + timeout->tv_sec * 1000000;
			}

			if (epoll_fds == 0){
				sceNetEpollDestroy(epollfd);
				response[1] = 0;
				if (sceKernelGetSystemTimeWide() - request->op_begin < timeout_usec){
					// try again
					break;
				}
				request_done = true;
				break;
			}

			response[1] = sceNetEpollWait(epollfd, events, sizeof(events) / sizeof(SceNetEpollEvent), timeout_usec);
			sceNetEpollDestroy(epollfd);

			if (response[1] < 0){
				request_done = true;
				break;
			}

			uint32_t readfds_new[8] = {0};
			uint32_t writefds_new[8] = {0};
			uint32_t exceptfds_new[8] = {0};

			bool has_event = false;
			for (int i = 0;i < response[1];i++){
				if (events[i].events & SCE_NET_EPOLLIN && readfds != NULL){
					has_event = true;
					psp_select_set_fd(readfds_new, events[i].data.fd, true);
				}
				if (events[i].events & SCE_NET_EPOLLOUT && writefds != NULL){
					has_event = true;
					psp_select_set_fd(writefds_new, events[i].data.fd, true);
				}

				#if LOG_CMD
				if (events[i].events & SCE_NET_EPOLLIN){
					readfds_out_log_offset += sprintf(&readfds_out_log[readfds_out_log_offset], "0x%x ", events[i].data.fd);
				}
				if (events[i].events & SCE_NET_EPOLLOUT){
					writefds_out_log_offset += sprintf(&writefds_out_log[writefds_out_log_offset], "0x%x ", events[i].data.fd);
				}
				#endif
			}

			if (!has_event){
				if (sceKernelGetSystemTimeWide() - request->op_begin < timeout_usec){
					// wait for next time
					break;
				}
			}
			request_done = true;

			if (readfds != NULL){
				memcpy(readfds, readfds_new, sizeof(readfds_new));
				kermit_pspemu_writeback_cache(readfds, sizeof(uint32_t) * 8);
			}
			if (writefds != NULL){
				memcpy(writefds, writefds_new, sizeof(writefds_new));
				kermit_pspemu_writeback_cache(writefds, sizeof(uint32_t) * 8);
			}
			if (exceptfds != NULL){
				memcpy(exceptfds, exceptfds_new, sizeof(exceptfds_new));
				kermit_pspemu_writeback_cache(exceptfds, sizeof(uint32_t) * 8);
			}

			#if LOG_CMD
			LOG("%s: select %d(%d) 0x%x(%s)(%s) 0x%x(%s)(%s) 0x%x 0x%x(%d), 0x%x\n", __func__, nfds, epoll_fds, readfds, readfds_log, readfds_out_log, writefds, writefds_log, writefds_out_log, exceptfds, timeout, timeout_usec, response[1]);
			#endif

			break;
		}
		case KERMIT_INET_SOCKET_ABORT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			response[1] = sceNetSocketAbort(sockfd, 0);
			request_done = true;

			#if LOG_CMD
			LOG("%s: SocketAbort 0x%x/0x%x, 0x%x\n", __func__, sockfd, psp_sockfd, response[1]);
			#endif

			break;
		}
		case KERMIT_INET_SOCKET_IOCTL:{
			int32_t psp_sockfd = *(int32_t*)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t command = *(uint32_t*)&request->args[1];
			void *data = request->args[2] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[2], KERMIT_ADDR_MODE_INOUT, 0x24);

			response[1] = sceNetSyscallIoctl_import(sockfd, command, data);
			request_done = true;
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(data, 0x24);
			}

			#if LOG_CMD
			LOG("%s: ioctl 0x%x/0x%x 0x%x 0x%x/0x%x, 0x%x\n", __func__, sockfd, psp_sockfd, command, data, *(uint32_t*)&request->args[2], response[1]);
			#endif

			break;
		}
		default:{
			LOG("%s: unknown command 0x%x\n", __func__, request->cmd);
			response[1] = -1;
			response[0] = -1;

			break;
		}
	}

	if (request_done){
		if (response[1] < 0 && response[0] != 0 && response[0] != EAGAIN){
			LOG("%s: cmd 0x%x gets error 0x%x\n", __func__, request->cmd, response[0]);
		}

		if (response[1] < 0 && response[0] == 0){
			response[0] = __vita_scenet_errno_to_errno(response[1]);
			response[1] = -1;
			if (response[0] != EBUSY && response[0] != EAGAIN)
				LOG("%s: cmd 0x%x gets error 0x%x\n", __func__, request->cmd, response[0]);
		}

		request->ret = *(uint64_t*)response;
		kermit_pspemu_writeback_cache(&request->ret, sizeof(&request->ret));

		asm volatile ("" : : : "memory");

		request->done = true;
		kermit_pspemu_writeback_cache(&request->done, sizeof(&request->done));

		return true;
	}
	return false;
}

static int inet_queue_worker(unsigned int args, void *argp){
	struct inet_worker *worker = *(struct inet_worker **)argp;

	while(!worker->should_stop){
		// Wait until we were signaled to work
		sceKernelWaitSema(worker->sema, 1, NULL);

		// Lock down the worker while working
		sceKernelLockMutex(worker->mutex, 1, 0);

		#if LOG_CMD
		char log_buf[128] = {0};
		int log_buf_offset = 0;
		for (int i = 0;i < sizeof(worker->queue) / sizeof(worker->queue[0]);i++){
			if (worker->queue[i] == NULL){
				continue;
			}
			log_buf_offset += sprintf(&log_buf[log_buf_offset], "0x%x ", worker->queue[i]->cmd);
		}
		LOG("%s: %d requests\n%s\n", __func__, worker->num_requests, log_buf);
		#endif

		for (int i = 0;i < sizeof(worker->queue) / sizeof(worker->queue[0]);i++){
			if (worker->queue[i] == NULL){
				continue;
			}
			bool request_done = handle_request(worker->queue[i], worker);
			if (request_done){
				worker->queue[i] = NULL;
				worker->num_requests--;
			}
		}

		sceKernelUnlockMutex(worker->mutex, 1);
	}

	return 0;
}

static int worker_ticker(unsigned int args, void *argp){
	while (true){
		for (int i = 0;i < num_workers;i++){
			sceKernelLockMutex(workers[i].mutex, 1, 0);
			if (workers[i].num_requests != 0){
				sceKernelSignalSema(workers[i].sema, 1);
			}
			sceKernelUnlockMutex(workers[i].mutex, 1);
		}
		sceKernelDelayThread(10000);
	}
	return 0;
}

int handle_inet_request(SceKermitRequest *request){
	#if 0
	log_request(request);
	#endif

	if (request->cmd == 0x34){
		// looks like it is for closing all psp sockets
		int num_active_psp_sockets = 0;
		int num_close_failure = 0;
		sceKernelLockMutex(sockfd_map_mutex, 1, 0);
		for (int i = 0;i < sizeof(sockfd_map) / sizeof(sockfd_map[0]);i++){
			if (sockfd_map[i] != -1){
				num_active_psp_sockets++;
				sceNetSocketAbort(sockfd_map[i], 0);
				int close_status = sceNetSocketClose(sockfd_map[i]);
				if (close_status != 0){
					LOG("%s: failed closing socket 0x%x, 0x%x\n", __func__, sockfd_map[i], close_status);
					num_close_failure++;
				}else{
					LOG("%s: closed 0x%x/0x%x\n", __func__, sockfd_map[i], i);
				}
				sockfd_map[i] = -1;
			}
		}
		sceKernelUnlockMutex(sockfd_map_mutex, 1);
		LOG("%s: command 0x%x, closed %d active psp socket(s), %d socket(s) refused to close\n", __func__, request->cmd, num_active_psp_sockets, num_close_failure);
		return 0;
	}

	if (request->cmd < KERMIT_INET_SOCKET || request->cmd > KERMIT_INET_SOCKET_IOCTL){
		#if LOG_CMD
		char args[256];
		int offset = 0;
		for (int i = 0;i < 14;i++){
			offset += sprintf(&args[offset], "0x%x ", (uint32_t)request->args[i]);
		}
		LOG("%s: unhandled cmd 0x%x, %s\n", __func__, request->cmd, args);
		#endif
		return 0;
	}

	struct request_slot *slot = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[0], KERMIT_ADDR_MODE_INOUT, sizeof(struct request_slot));

	struct inet_worker *worker = &workers[0];

	while (true){
		int free_slot = -1;
		sceKernelLockMutex(worker->mutex, 1, 0);
		for (int i = 0;i < sizeof(worker->queue) / sizeof(worker->queue[0]);i++){
			if (worker->queue[i] == NULL){
				free_slot = i;
				break;
			}
		}

		if (free_slot == -1){
			// can't queue!
			sceKernelUnlockMutex(worker->mutex, 1);
			sceKernelSignalSema(worker->sema, 1);
			sceKernelDelayThread(1000);
			continue;
		}

		worker->queue[free_slot] = slot;
		slot->op_begin = 0;
		slot->in_progress = 0;
		worker->num_requests++;

		asm volatile ("" : : : "memory");

		sceKernelUnlockMutex(worker->mutex, 1);
		sceKernelSignalSema(worker->sema, 1);

		// Work request queued, stop blocking the message pipe
		kermit_respond_request(KERMIT_MODE_WLAN, request, 0);

		break;
	}

	#if 0
	int free_worker = -1;
	int shortest_queue_worker = -1;
	for (int i = 0;i < num_workers;i++){
		if (free_worker == -1){
			int lock_status = sceKernelTryLockMutex(workers[i].mutex, 1);
			if (lock_status == 0){
				if (workers[i].num_requests == 0){
					free_worker = i;
				}
				sceKernelUnlockMutex(workers[i].mutex, 1);
			}
		}

		// Not a very reliable fallback, the worker could still be blocking forever
		if (shortest_queue_worker == -1 || workers[shortest_queue_worker].num_requests > workers[i].num_requests){
			shortest_queue_worker = i;
		}
	}

	struct inet_worker *worker = NULL;

	if (free_worker != -1){
		worker = &workers[free_worker];
	}else{
		LOG("%s: warning, queuing request onto a non-free worker\n", __func__);
		worker = &workers[shortest_queue_worker];
	}

	while (true){
		// Lock worker and queue work into it
		sceKernelLockMutex(worker->mutex, 1, 0);

		if (worker->num_requests == sizeof(worker->queue) / sizeof(worker->queue[0])){
			// not good, in fact very bad
			LOG("%s: work queue is full! waiting...\n", __func__);
			sceKernelUnlockMutex(worker->mutex, 1);
			sceKernelDelayThread(10000);
			continue;
		}
		worker->queue[worker->num_requests] = slot;
		#if 0
		char args[256];
		int offset = 0;
		for (int i = 0;i < 14;i++){
			offset += sprintf(&args[offset], "0x%x ", *(uint32_t*)&worker->queue[worker->num_requests]->args[i]);
		}
		LOG("%s: queuing request addr 0x%x, 0x%x %s\n", __func__, worker->queue[worker->num_requests], worker->queue[worker->num_requests]->cmd, args);
		#endif

		worker->num_requests++;

		// Work request queued, stop blocking the message pipe
		kermit_respond_request(KERMIT_MODE_WLAN, request, 0);

		// Let the worker continue working
		sceKernelSignalSema(worker->sema, 1);
		sceKernelUnlockMutex(worker->mutex, 1);

		break;
	}
	#endif

	return 1;
}

int inet_init(){
	sockfd_map_mutex = sceKernelCreateMutex("inet sockfd remap mutex", 0, 0, NULL);
	if (sockfd_map_mutex < 0){
		LOG("%s: failed initializing sockfd map mutex, 0x%x\n", __func__, sockfd_map_mutex);
		return 0;
	}

	for (int i = 0;i < sizeof(sockfd_map) / sizeof(int32_t);i++){
		sockfd_map[i] = -1;
	}

	for (int i = 0;i < sizeof(workers) / sizeof(workers[0]);i++){
		workers[num_workers].num_requests = 0;
		workers[num_workers].should_stop = false;
		workers[num_workers].busy = false;
		workers[num_workers].id = i;
		for(int j = 0;j < sizeof(workers[num_workers].queue) / sizeof(workers[num_workers].queue[0]);j++){
			workers[num_workers].queue[j] = NULL;
		}

		workers[num_workers].sema = sceKernelCreateSema("inet worker sema", 0, 0, 65535, NULL);
		if (workers[num_workers].sema < 0){
			LOG("%s: failed creating sema, 0x%x\n", __func__, workers[num_workers].sema);
			return num_workers;
		}

		workers[num_workers].mutex = sceKernelCreateMutex("inet worker mutex", 0, 0, NULL);
		if (workers[num_workers].mutex < 0){
			LOG("%s: failed creating worker mutex, 0x%x\n", __func__, workers[num_workers].mutex);
			sceKernelDeleteSema(workers[num_workers].sema);
			return num_workers;
		}

		workers[num_workers].tid = sceKernelCreateThread("inet worker", inet_queue_worker, 0x10000100, 0x10000, 0, 0, NULL);
		if (workers[num_workers].tid < 0){
			LOG("%s: failed creating queue worker, 0x%x\n", __func__, workers[num_workers].tid);
			sceKernelDeleteSema(workers[num_workers].sema);
			sceKernelDeleteMutex(workers[num_workers].mutex);
			return num_workers;
		}

		struct inet_worker *worker_ptr = &workers[num_workers];
		int start_status = sceKernelStartThread(workers[num_workers].tid, sizeof(struct inet_worker **), &worker_ptr);
		if (start_status != 0){
			LOG("%s: failed starting queue worker, 0x%x\n", __func__, start_status);
			sceKernelDeleteSema(workers[num_workers].sema);
			sceKernelDeleteMutex(workers[num_workers].mutex);
			sceKernelDeleteThread(workers[num_workers].tid);
			return num_workers;
		}

		num_workers++;
	}

	SceUID tid = sceKernelCreateThread("inet worker ticker", worker_ticker, 0x10000100, 0x10000, 0, 0, NULL);
	if (tid < 0){
		LOG("%s: failed creating worker ticker, 0x%x\n", __func__, tid);
		for(int i = 0;i < num_workers;i++){
			workers[i].should_stop = true;
		}
		return 0;
	}
	int start_status = sceKernelStartThread(tid, 0, NULL);
	if (start_status != 0){
		LOG("%s: failed starting worker ticker, 0x%x\n", __func__, tid);
		for(int i = 0;i < num_workers;i++){
			workers[i].should_stop = true;
		}
		return 0;
	}

	return num_workers;
}
