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

int handle_inet_request(SceKermitRequest *request){
	LOG("%s: 0x%x not implemented\n", __func__, request->cmd);
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
