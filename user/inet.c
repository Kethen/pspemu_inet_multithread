#include <vitasdk.h>

#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "kermit.h"

struct inet_worker{
	SceUID sema;
	SceUID queue_mutex;
	SceKermitRequest *queue[512];
	int num_requests;
	SceUID tid;
	bool should_stop;
};

struct inet_worker workers[8] = {0};
int num_workers = 0;

static int last_worker_used = 0;

static void log_request(SceKermitRequest *request){
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

	LOG("%s: unknown 0x%x 0x%x 0x%x 0x%x 0x%x\n", __func__, request->cmd, (uint32_t)request->args[0], (uint32_t)request->args[1], (uint32_t)request->args[2], (uint32_t)request->args[3]);
}

int handle_inet_request(SceKermitRequest *request){
	#if 1
	log_request(request);
	#endif

	return 0;
}

static int inet_queue_worker(unsigned int args, void *argp){
	struct inet_worker *worker = *(struct inet_worker **)argp;

	while(!worker->should_stop){
		// Wait until we were signaled to work
		sceKernelWaitSema(worker->sema, 1, 0);

		// Acquire the queue and copy it
		sceKernelLockMutex(worker->queue_mutex, 1, 0);
		int num_requests = worker->num_requests;
		SceKermitRequest *queue[sizeof(worker->queue) / sizeof(worker->queue[0])];
		memcpy(queue, worker->queue, sizeof(SceKermitRequest *) * num_requests);
		sceKernelUnlockMutex(worker->queue_mutex, 1);

		for(int i = 0;i < num_requests;i++){
			// TODO perform work
		}
	}

	return 0;
}

int inet_init(){
	last_worker_used = 0;

	for(int i = 0;i < sizeof(workers) / sizeof(workers[0]);i++){
		workers[num_workers].num_requests = 0;
		workers[num_workers].should_stop = false;

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
