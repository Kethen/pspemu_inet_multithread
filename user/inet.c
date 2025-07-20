#include <vitasdk.h>

#include <psp2/net/net.h>

#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "kermit.h"
#include "error.h"

#include <errno.h>

struct inet_worker{
	SceUID sema;
	SceUID queue_mutex;
	struct request_slot *queue[16];
	int num_requests;
	SceUID tid;
	bool should_stop;
	bool busy;
};

struct inet_worker workers[16] = {0};
int num_workers = 0;

static int last_worker_used = 0;

// the vita can do up to 1024 sockets?
int32_t sockfd_map[255];
SceUID sockfd_map_mutex = -1;

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

int handle_inet_request(SceKermitRequest *request){
	#if 1
	log_request(request);
	#endif

	if (request->cmd < KERMIT_INET_SOCKET || request->cmd > KERMIT_INET_SOCKET_ABORT){
		char args[256];
		int offset = 0;
		for (int i = 0;i < 14;i++){
			offset += sprintf(&args[offset], "0x%x ", (uint32_t)request->args[i]);
		}
		LOG("%s: unhandled cmd 0x%x, %s\n", __func__, request->cmd, args);
		return 0;
	}

	int free_worker = -1;
	int shortest_queue_worker = -1;
	for (int i = 0;i < sizeof(workers) / sizeof(struct inet_worker);i++){
		if (!workers[i].busy){
			free_worker = i;
			break;
		}
		if (shortest_queue_worker == -1 || workers[shortest_queue_worker].num_requests > workers[i].num_requests){
			shortest_queue_worker = i;
		}
	}

	struct inet_worker *worker = NULL;
	if (free_worker != -1){
		worker = &workers[free_worker];
	}else{
		worker = &workers[shortest_queue_worker];
	}

	while (true){
		sceKernelLockMutex(worker->queue_mutex, 1, 0);

		if (worker->num_requests == sizeof(worker->queue) / sizeof(worker->queue[0])){
			// not good, in fact very bad
			LOG("%s: work queue is full! waiting...\n", __func__);
			sceKernelUnlockMutex(worker->queue_mutex, 1);
			sceKernelDelayThread(10000);
			continue;
		}

		worker->queue[worker->num_requests] = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[0], KERMIT_ADDR_MODE_IN, sizeof(struct request_slot));
		char args[256];
		int offset = 0;
		for (int i = 0;i < 14;i++){
			offset += sprintf(&args[offset], "0x%x ", *(uint32_t*)&worker->queue[worker->num_requests]->args[i]);
		}
		LOG("%s: queuing request addr 0x%x, 0x%x %s\n", __func__, worker->queue[worker->num_requests], worker->queue[worker->num_requests]->cmd, args);

		worker->num_requests++;
		kermit_respond_request(KERMIT_MODE_WLAN, request, 0);

		sceKernelSignalSema(worker->sema, 1);

		sceKernelUnlockMutex(worker->queue_mutex, 1);
		break;
	}

	return 1;
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
	if (psp_sockfd < 0){
		return -1;
	}
	if (psp_sockfd >= sizeof(sockfd_map) / sizeof(int32_t)){
		return -1;
	}
	sceKernelLockMutex(sockfd_map_mutex, 1, 0);
	int sockfd = sockfd_map[psp_sockfd];
	sceKernelUnlockMutex(sockfd_map_mutex, 1);
	return sockfd;
}

static int32_t map_sockfd(int sockfd){
	sceKernelLockMutex(sockfd_map_mutex, 1, 0);
	for (int i = 0;i < sizeof(sockfd_map) / sizeof(int32_t);i++){
		if (sockfd_map[i] == -1){
			sockfd_map[i] = sockfd;
			sceKernelUnlockMutex(sockfd_map_mutex, 1);
			return i;
		}
	}
	sceKernelUnlockMutex(sockfd_map_mutex, 1);
	return -1;
}

static void remove_sockfd(int psp_sockfd){
	if (psp_sockfd < 0){
		return;
	}
	if (psp_sockfd >= sizeof(sockfd_map) / sizeof(int32_t)){
		return;
	}
	sceKernelLockMutex(sockfd_map_mutex, 1, 0);
	sockfd_map[psp_sockfd] = -1;
	sceKernelUnlockMutex(sockfd_map_mutex, 1);
}

static void handle_request(struct request_slot *request){
	int32_t response[2] = {0};

	switch(request->cmd){
		case KERMIT_INET_SOCKET:{
			int32_t type = *(int32_t*)&request->args[1];
			int sockfd = sceNetSocket("pspemu_inet_multithread", SCE_NET_AF_INET, type, 0);
			int psp_sockfd = map_sockfd(sockfd);
			if (psp_sockfd == -1){
				sceNetSocketClose(sockfd);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}
			response[1] = psp_sockfd;

			break;
		}
		case KERMIT_INET_BIND:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
			SceNetSockaddrIn addr = {0};
			addr.sin_len = psp_addr->sin_len;
			addr.sin_family = SCE_NET_AF_INET;
			addr.sin_port = psp_addr->sin_port;
			addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
			response[1] = sceNetBind(sockfd, (void *)&addr, sizeof(SceNetSockaddrIn));

			break;
		}
		case KERMIT_INET_LISTEN:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t backlog = *(int32_t *)&request->args[1];
			response[1] = sceNetListen(sockfd, backlog);

			break;
		}
		case KERMIT_INET_ACCEPT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetSockaddrIn *addr_out = request->args[1] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, sizeof(SceNetSockaddrIn));
			int32_t *addrlen_in_out = request->args[2] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			int accept_sockfd = sceNetAccept(sockfd, (void *)addr_out, addrlen_in_out);
			if (accept_sockfd < 0){
				response[1] = accept_sockfd;
				break;
			}
			int psp_accept_sockfd = map_sockfd(accept_sockfd);
			if (psp_accept_sockfd == -1){
				sceNetSocketClose(accept_sockfd);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}
			response[1] = psp_accept_sockfd;
			if (addr_out != NULL)
				kermit_pspemu_writeback_cache(addr_out, sizeof(SceNetSockaddrIn));
			if (addrlen_in_out != NULL)
				kermit_pspemu_writeback_cache(addrlen_in_out, sizeof(int32_t));

			break;
		}
		case KERMIT_INET_CONNECT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
			SceNetSockaddrIn addr = {0};
			addr.sin_len = psp_addr->sin_len;
			addr.sin_family = SCE_NET_AF_INET;
			addr.sin_port = psp_addr->sin_port;
			addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
			int32_t addrlen = *(int32_t*)&request->args[2];
			response[1] = sceNetConnect(sockfd, (void *)&addr, addrlen);

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
			response[1] = sceNetSetsockopt(sockfd, level, optname, optval, optlen);

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
			response[1] = sceNetGetsockopt(sockfd, level, optname, optval_out, optlen_in_out);
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(optlen_in_out, sizeof(int32_t));
				kermit_pspemu_writeback_cache(optval_out, *optlen_in_out);
			}

			break;
		}
		case KERMIT_INET_GETSOCKNAME:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			int32_t *addrlen_in_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			SceNetSockaddrIn *addr_out = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, *addrlen_in_out);
			response[1] = sceNetGetsockname(sockfd, (void *)addr_out, addrlen_in_out);
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
			response[1] = sceNetSend(sockfd, buf, size, flags);

			break;
		}
		case KERMIT_INET_SENDTO:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t *)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_IN, size);
			int32_t flags = *(int32_t *)&request->args[3];
			SceNetSockaddrIn *psp_addr = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[4], KERMIT_ADDR_MODE_IN, sizeof(SceNetSockaddrIn));
			SceNetSockaddrIn addr = {0};
			addr.sin_len = psp_addr->sin_len;
			addr.sin_family = SCE_NET_AF_INET;
			addr.sin_port = psp_addr->sin_port;
			addr.sin_addr.s_addr = psp_addr->sin_addr.s_addr;
			response[1] = sceNetSendto(sockfd, buf, size, flags, (void *)&addr, sizeof(SceNetSockaddrIn));

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
				addr.sin_len = psp_addr->sin_len;
				addr.sin_family = SCE_NET_AF_INET;
				addr.sin_port = psp_addr->sin_port;
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
			response[1] = sceNetSendmsg(sockfd, &msg, flags);

			break;
		}
		case KERMIT_INET_RECV:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t*)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, size);
			int32_t flags = *(int32_t *)&request->args[3];
			response[1] = sceNetRecv(sockfd, buf, size, flags);
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(buf, size);
			}

			break;
		}
		case KERMIT_INET_RECVFROM:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			uint32_t size = *(uint32_t*)&request->args[2];
			void *buf = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[1], KERMIT_ADDR_MODE_OUT, size);
			int32_t flags = *(int32_t *)&request->args[3];
			int32_t *addrlen_in_out = request->args[5] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[5], KERMIT_ADDR_MODE_INOUT, sizeof(int32_t));
			SceNetSockaddrIn *addr_out = request->args[4] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t *)&request->args[4], KERMIT_ADDR_MODE_OUT, *addrlen_in_out);
			response[1] = sceNetRecvfrom(sockfd, buf, size, flags, (void *)addr_out, addrlen_in_out);
			if (response[1] >= 0){
				kermit_pspemu_writeback_cache(buf, size);
				if (addrlen_in_out != NULL)
					kermit_pspemu_writeback_cache(addrlen_in_out, sizeof(int32_t));
				if (addrlen_in_out != NULL && addr_out != NULL)
					kermit_pspemu_writeback_cache(addr_out, *addrlen_in_out);
			}

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

			break;
		}
		case KERMIT_INET_CLOSE_WITH_RST:
		case KERMIT_INET_CLOSE:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			response[1] = sceNetSocketClose(sockfd);
			if (response[1] >= 0){
				remove_sockfd(psp_sockfd);
			}

			break;
		}
		case KERMIT_INET_POLL:{
			int32_t nfds = *(int32_t*)&request->args[1];
			struct psp_poll_fd *fds = kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[0], KERMIT_ADDR_MODE_INOUT, nfds * sizeof(struct psp_poll_fd));
			uint32_t timeout = *(uint32_t*)&request->args[2];

			SceNetEpollEvent events[255] = {0};

			if (nfds > sizeof(events) / sizeof(SceNetEpollEvent)){
				LOG("%s: too many fds on poll, %d\n", __func__, nfds);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}

			if (timeout < 0){
				response[1] = -1;
				response[0] = EINVAL;
			}

			int epollfd = sceNetEpollCreate("pspemu_inet_multithread poll", 0);
			if (epollfd < 0){
				LOG("%s: failed creating epoll instance for poll, 0x%x\n", __func__, epollfd);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}

			int epoll_fds = 0;
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
					continue;
				}

				event.data.fd = i;

				sceNetEpollControl(epollfd, SCE_NET_EPOLL_CTL_ADD, sockfd, &event);
				epoll_fds++;
			}

			uint32_t timeout_usec = timeout * 1000;

			if (epoll_fds == 0){
				sceNetEpollDestroy(epollfd);
				response[1] = 0;
				sceKernelDelayThread(timeout_usec);
				break;
			}

			response[1] = sceNetEpollWait(epollfd, events, sizeof(events) / sizeof(SceNetEpollEvent), timeout_usec);
			sceNetEpollDestroy(epollfd);

			if (response[1] < 0){
				break;
			}

			for (int i = 0;i < response[1];i++){
				if (events[i].events & SCE_NET_EPOLLIN){
					fds[events[i].data.fd].revents |= POLLIN | POLLRDNORM;
				}
				if (events[i].events & SCE_NET_EPOLLOUT){
					fds[events[i].data.fd].revents |= POLLOUT;
				}
				if (events[i].events & SCE_NET_EPOLLERR){
					fds[events[i].data.fd].revents |= POLLERR;
				}
				if (events[i].events & SCE_NET_EPOLLHUP){
					fds[events[i].data.fd].revents |= POLLHUP;
				}
			}

			kermit_pspemu_writeback_cache(fds, nfds * sizeof(struct psp_poll_fd));

			break;
		}
		case KERMIT_INET_SELECT:{
			int32_t nfds = *(int32_t *)&request->args[0];
			uint32_t *readfds = *(uint32_t*)&request->args[1] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[1], KERMIT_ADDR_MODE_INOUT, sizeof(uint32_t) * 8);
			uint32_t *writefds = *(uint32_t*)&request->args[2] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[2], KERMIT_ADDR_MODE_INOUT, sizeof(uint32_t) * 8);
			uint32_t *exceptfds = *(uint32_t*)&request->args[3] == 0 ? NULL : kermit_get_pspemu_addr_from_psp_addr(*(uint32_t*)&request->args[3], KERMIT_ADDR_MODE_INOUT, sizeof(uint32_t) * 8);
			uint32_t timeout = *(uint32_t *)&request->args[4];

			SceNetEpollEvent events[255] = {0};

			if (nfds > sizeof(events) / sizeof(SceNetEpollEvent) || nfds < 1){
				response[1] = -1;
				response[0] = EINVAL;
			}

			if (timeout < 0){
				response[1] = -1;
				response[0] = EINVAL;
			}

			int epollfd = sceNetEpollCreate("pspemu_inet_multithread select", 0);
			if (epollfd < 0){
				LOG("%s: failed creating epoll instance for select, 0x%x\n", __func__, epollfd);
				response[1] = -1;
				response[0] = ENOMEM;
				break;
			}

			int epoll_fds = 0;
			for (int i = 0;i < nfds;i++){
				SceNetEpollEvent event = {0};

				// only do these for now, since they map correctly to epoll
				if (readfds != NULL && psp_select_fd_is_set(readfds, i)){
					event.events |= SCE_NET_EPOLLIN;
					psp_select_set_fd(readfds, i, false);
				}
				if (writefds != NULL && psp_select_fd_is_set(writefds, i)){
					event.events |= SCE_NET_EPOLLOUT;
					psp_select_set_fd(writefds, i, false);
				}
				// hm, what about exceptfds
				if (exceptfds != NULL)
					psp_select_set_fd(exceptfds, i, false);

				if (event.events == 0){
					continue;
				}

				int sockfd = get_sockfd(i);
				if (sockfd == -1){
					response[1] = -1;
					response[0] = EBADF;
					break;
				}

				event.data.fd = i;

				sceNetEpollControl(epollfd, SCE_NET_EPOLL_CTL_ADD, sockfd, &event);
				epoll_fds++;
			}

			uint32_t timeout_usec = timeout * 1000;

			if (epoll_fds == 0){
				sceNetEpollDestroy(epollfd);
				response[1] = 0;
				sceKernelDelayThread(timeout_usec);
				break;
			}

			response[1] = sceNetEpollWait(epollfd, events, sizeof(events) / sizeof(SceNetEpollEvent), timeout_usec);
			sceNetEpollDestroy(epollfd);

			if (response[1] < 0){
				break;
			}

			if (response[1] != 0){
				for (int i = 0;i < nfds;i++){
					if (events[i].events & SCE_NET_EPOLLIN && readfds != NULL){
						psp_select_set_fd(readfds, events[i].data.fd, true);
					}
					if (events[i].events & SCE_NET_EPOLLOUT && writefds != NULL){
						psp_select_set_fd(writefds, events[i].data.fd, true);
					}
				}
			}

			if (readfds != NULL)
				kermit_pspemu_writeback_cache(readfds, sizeof(uint32_t) * 8);
			if (writefds != NULL)
				kermit_pspemu_writeback_cache(writefds, sizeof(uint32_t) * 8);
			if (exceptfds != NULL)
				kermit_pspemu_writeback_cache(exceptfds, sizeof(uint32_t) * 8);

			break;
		}
		case KERMIT_INET_SOCKET_ABORT:{
			int32_t psp_sockfd = *(int32_t *)&request->args[0];
			int32_t sockfd = get_sockfd(psp_sockfd);
			response[1] = sceNetSocketAbort(sockfd, 0);

			break;
		}
		default:{
			LOG("%s: unknown command 0x%x\n", __func__, request->cmd);
			response[1] = -1;
			response[0] = -1;
			break;
		}
	}

	if (response[1] < 0 && response[0] == 0){
		response[0] = __vita_scenet_errno_to_errno(response[1]);
		response[1] = -1;
		LOG("%s: cmd 0x%x gets error 0x%x\n", __func__, request->cmd, response[0]);
	}

	request->ret = *(uint64_t*)response;
	kermit_pspemu_writeback_cache(&request->ret, sizeof(&request->ret));

	asm volatile ("" : : : "memory");

	request->done = true;
	kermit_pspemu_writeback_cache(&request->done, sizeof(&request->done));

}

static int inet_queue_worker(unsigned int args, void *argp){
	struct inet_worker *worker = *(struct inet_worker **)argp;

	while(!worker->should_stop){
		// Wait until we were signaled to work
		sceKernelWaitSema(worker->sema, 1, 0);

		worker->busy = true;

		asm volatile ("" : : : "memory");

		// Acquire the queue and copy it
		sceKernelLockMutex(worker->queue_mutex, 1, 0);
		int num_requests = worker->num_requests;
		struct request_slot *queue[sizeof(worker->queue) / sizeof(worker->queue[0])];
		memcpy(queue, worker->queue, sizeof(struct request_slot *) * num_requests);
		worker->num_requests = 0;
		sceKernelUnlockMutex(worker->queue_mutex, 1);

		for (int i = 0;i < num_requests;i++){
			handle_request(queue[i]);
		}

		asm volatile ("" : : : "memory");

		worker->busy = false;
	}

	return 0;
}

int inet_init(){
	last_worker_used = 0;

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

		workers[num_workers].sema = sceKernelCreateSema("inet worker sema", 0, 0, 65535, NULL);
		if (workers[num_workers].sema < 0){
			LOG("%s: failed creating sema, 0x%x\n", __func__, workers[num_workers].sema);
			return num_workers;
		}

		workers[num_workers].queue_mutex = sceKernelCreateMutex("inet worker mutex", 0, 0, NULL);
		if (workers[num_workers].queue_mutex < 0){
			LOG("%s: failed creating queue mutex, 0x%x\n", __func__, workers[num_workers].queue_mutex);
			sceKernelDeleteSema(workers[num_workers].sema);
			return num_workers;
		}

		workers[num_workers].tid = sceKernelCreateThread("inet worker", inet_queue_worker, 0x10000100, 0x10000, 0, 0, NULL);
		if (workers[num_workers].tid < 0){
			LOG("%s: failed creating queue worker, 0x%x\n", __func__, workers[num_workers].tid);
			sceKernelDeleteSema(workers[num_workers].sema);
			sceKernelDeleteMutex(workers[num_workers].queue_mutex);
			return num_workers;
		}

		struct inet_worker *worker_ptr = &workers[num_workers];
		sceKernelStartThread(workers[num_workers].tid, sizeof(struct inet_worker **), &worker_ptr);

		num_workers++;
	}

	return num_workers;
}
