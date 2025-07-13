#include <pspkernel.h>
#include <psptypes.h>
#include <pspthreadman.h>
#include <pspsdk.h>
#include <pspnet_apctl.h>
#include <pspnet.h>
#include <pspnet_inet.h>
#include <pspnet_resolver.h>
#include <psputility_netmodules.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"

PSP_MODULE_INFO("WLAN test", 0x1000, 1, 1);
PSP_HEAP_SIZE_KB(1000);

#define max_lines

/* Exit callback */
int exit_callback(int arg1, int arg2, void *common)
{
	sceKernelExitGame();

	return 0;
}

/* Callback thread */
int CallbackThread(SceSize args, void *argp)
{
	int cbid;

	cbid = sceKernelCreateCallback("Exit Callback", exit_callback, NULL);
	sceKernelRegisterExitCallback(cbid);

	sceKernelSleepThreadCB();

	return 0;
}

/* Sets up the callback thread and returns its thread id */
int SetupCallbacks(void)
{
	int thid = 0;

	thid = sceKernelCreateThread("update_thread", CallbackThread, 0x11, 0xFA0, THREAD_ATTR_USER, 0);
	if(thid >= 0)
	{
		sceKernelStartThread(thid, 0, 0);
	}

	return thid;
}

int init_inet(){
	int net_init_status = sceNetInit(0x20000, 0x2A, 0, 0x2A, 0);;
	if (net_init_status < 0){
		LOG("%s: failed initializing net, 0x%x\n", __func__, net_init_status);
		return net_init_status;
	}

	int inet_init_status = sceNetInetInit();
	if (inet_init_status != 0){
		LOG("%s: failed initializing inet, 0x%x\n", __func__, inet_init_status);
		return inet_init_status;
	}

	int resolver_init_status = sceNetResolverInit();
	if (resolver_init_status != 0){
		LOG("%s: failed initializing resolver, 0x%x\n", __func__, resolver_init_status);
		return resolver_init_status;
	}
	
	int apctl_init_status = sceNetApctlInit(0x1800, 0x30);
	if (apctl_init_status != 0){
		LOG("%s: failed initializing apctl, 0x%x\n", __func__, apctl_init_status);
		return apctl_init_status;
	}
	return 0;
}

void term_inet(){
	sceNetApctlTerm();
	sceNetResolverTerm();
	sceNetInetTerm();
	sceNetTerm();
}

void test(){
	sceUtilityLoadNetModule(PSP_NET_MODULE_COMMON);
	sceUtilityLoadNetModule(PSP_NET_MODULE_INET);	

	int conn_index = 1;

	while(1){
		int net_init_result = init_inet();
		if (net_init_result < 0){
			return;
		}

		LOG("%s: connecting to index %d\n", __func__, conn_index);
		int connect_result = sceNetApctlConnect(conn_index);
		if (connect_result < 0){
			LOG("%s: failed connecting to ap, 0x%x\n", __func__, connect_result);
			term_inet();
			sceKernelDelayThread(10000);
			conn_index++;
			if (conn_index == 33){
				conn_index = 1;
			}

			continue;
		}

		int state_before = PSP_NET_APCTL_STATE_DISCONNECTED;
		int retry = 0;
		uint64_t begin = sceKernelGetSystemTimeWide();
		while(1){
			int state = PSP_NET_APCTL_STATE_DISCONNECTED;
			int get_state_result = sceNetApctlGetState(&state);
			if (get_state_result < 0){
				LOG("%s: failed getting apctl state, 0x%x\n", __func__, get_state_result);
				return;
			}
			if (state != state_before){
				union SceNetApctlInfo info = {0};
				int get_info_result = sceNetApctlGetInfo(PSP_NET_APCTL_INFO_SECURITY_TYPE, &info);
				int security_type = info.securityType;
				if (get_info_result < 0){
					LOG("%s: apctl state 0x%x -> 0x%x, failed getting apctl info 0x%x\n", __func__, state_before, state, get_info_result);
				}else{
					sceNetApctlGetInfo(PSP_NET_APCTL_INFO_SSID, &info);
					LOG("%s: apctl state 0x%x -> 0x%x, ssid %s security type %d\n", __func__, state_before, state, info.ssid, security_type);
				}
			}
			if (state == PSP_NET_APCTL_STATE_GOT_IP){
				LOG("%s: connected to ap\n", __func__);
				break;
			}
			if (state == PSP_NET_APCTL_STATE_DISCONNECTED && state_before != PSP_NET_APCTL_STATE_DISCONNECTED){
				LOG("%s: failed connecting to ap, disconnected\n", __func__);
				retry = 1;
				break;
			}
			if (sceKernelGetSystemTimeWide() - begin > 1000000 * 10){
				LOG("%s: struggling to get an ip, retrying\n", __func__);
				sceNetApctlDisconnect();
				sceKernelDelayThread(1000000);
				retry = 1;
				break;
			}
			state_before = state;
			sceKernelDelayThread(10000);
		}
		if (retry){
			term_inet();
			sceKernelDelayThread(1000000);
			conn_index++;
			if (conn_index == 33){
				conn_index = 1;
			}
			
			continue;
		}
		break;
	}

	LOG("%s: creating socket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_STREAM, 0);
	int sock = sceNetInetSocket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0){
		LOG("%s: failed creating socket, 0x%x\n", __func__, sock);
		return;
	}

	struct sockaddr_in addr = {0};
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(27015);
	addr.sin_addr.s_addr = sceNetInetInetAddr("127.0.0.1");

	LOG("%s: binding socket, %d, 0x%x, %d\n", __func__, sock, &addr, sizeof(addr));
	int bind_result = sceNetInetBind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (bind_result < 0){
		LOG("%s: failed binding socket, 0x%x\n", __func__, bind_result);
		return;
	}
}

int test_thread(SceSize args, void *argp){
	test();
	return 0;
}

int main(void) {
	INIT_LOG();
	SetupCallbacks();

	sceKernelDelayThread(1000000 * 3);

	int tid = sceKernelCreateThread("test_thread", test_thread, 0x18, 0x10000, 0, NULL);
	if (tid < 0){
		LOG("%s: failed creating test thread, 0x%x\n", __func__, tid);
	}
	sceKernelStartThread(tid, 0, NULL);

	while(1){
		sceKernelDelayThread(1000000);
	}

	return 0;
}
