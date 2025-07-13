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
#include <netinet/tcp.h>

#include <string.h>

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

const char test_data[] = "abcdefg";

typedef int (*trans_function)(int sock, uint8_t *buf, int size, int flags);

void tcp_send(){
	LOG("%s: sceNetInetSocket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_STREAM, 0);
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

	int sock_opt = 1;
	LOG("%s: sceNetInetSetsockopt %d %d 0x%x %d\n", __func__, sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, sizeof(sock_opt));
	int set_sockopt_status = sceNetInetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, (socklen_t)sizeof(sock_opt));
	if (set_sockopt_status < 0){
		LOG("%s: failed setting tcp nodelay socket option, 0x%x\n", __func__, set_sockopt_status);
		return;
	}

	sock_opt = 1;
	LOG("%s: sceNetInetSetsockopt %d %d 0x%x %d\n", __func__, sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, sizeof(sock_opt));
	set_sockopt_status = sceNetInetSetsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, (socklen_t)sizeof(sock_opt));
	if (set_sockopt_status < 0){
		LOG("%s: failed setting keepalive socket option, 0x%x\n", __func__, set_sockopt_status);
		return;
	}

	socklen_t sockopt_len = sizeof(int);
	LOG("%s: sceNetInetGetsockopt %d %d 0x%x %d\n", __func__, sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, sizeof(sock_opt));
	int get_sockopt_status = sceNetInetGetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, &sockopt_len);
	if (get_sockopt_status < 0){
		LOG("%s: failed getting socket option, 0x%x\n", __func__, get_sockopt_status);
		return;
	}
	if (!sock_opt){
		LOG("%s: tcp nodelay socket option was not set properly, 0x%x\n", __func__, sock_opt);
		return;
	}

	sockopt_len = sizeof(int);
	LOG("%s: sceNetInetGetsockopt %d %d 0x%x %d\n", __func__, sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, sizeof(sock_opt));
	get_sockopt_status = sceNetInetGetsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, &sockopt_len);
	if (get_sockopt_status < 0){
		LOG("%s: failed getting socket option, 0x%x\n", __func__, get_sockopt_status);
		return;
	}
	if (!sock_opt){
		LOG("%s: keepalive socket option was not set properly, 0x%x\n", __func__, sock_opt);
		return;
	}

	LOG("%s: sceNetInetConnect %d, 0x%x, %d\n", __func__, sock, &addr, sizeof(addr));
	int connect_status = sceNetInetConnect(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (connect_status < 0){
		LOG("%s: failed connecting, 0x%x\n", __func__, connect_status);
		return;
	}

	LOG("%s: sceNetInetSend %d 0x%x %d %d\n", __func__, sock, test_data, sizeof(test_data), 0);
	int send_status = sceNetInetSend(sock, test_data, sizeof(test_data), 0);
	if (send_status < 0){
		LOG("%s: failed sending, 0x%x\n", __func__, send_status);
		return;
	}
	if (send_status != sizeof(test_data)){
		LOG("%s: sent %d bytes, expected %d\n", __func__, send_status, sizeof(test_data));
	}

	sceKernelDelayThread(1000000 * 2);
	LOG("%s: sceNetInetClose %d\n", __func__, sock);
	sceNetInetClose(sock);
}

int tcp_send_thread(SceSize args, void *argp){
	tcp_send();
	return 0;
}

void test_tcp(){
	LOG("%s: sceNetInetSocket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_STREAM, 0);
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

	LOG("%s: sceNetInetBind %d 0x%x %d\n", __func__, sock, &addr, sizeof(addr));
	int bind_result = sceNetInetBind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (bind_result < 0){
		LOG("%s: failed binding socket, 0x%x\n", __func__, bind_result);
		return;
	}

	LOG("%s: sceNetInetListen %d %d\n", __func__, sock, 100);
	int listen_result = sceNetInetListen(sock, 100);
	if (listen_result < 0){
		LOG("%s: failed setting up listen, 0x%x\n", __func__, listen_result);
		return;
	}

	int tid = sceKernelCreateThread("connect thread", tcp_send_thread, 0x18, 0x10000, 0, NULL);
	if(tid < 0){
		LOG("%s: failed creating connection pair thread, 0x%x\n", __func__, tid);
		return;
	}
	sceKernelStartThread(tid, 0, NULL);

	sceKernelDelayThread(1000000);

	struct sockaddr_in incoming_addr = {0};
	socklen_t addr_len = sizeof(incoming_addr);
	LOG("%s: sceNetInetAccept %d 0x%x 0x%x\n", __func__, sock, &incoming_addr, &addr_len);
	int accept_sock = sceNetInetAccept(sock, (struct sockaddr*)&incoming_addr, &addr_len);
	if (accept_sock < 0){
		LOG("%s: failed accepting connection, 0x%x\n", __func__, accept_sock);
		return;
	}

	char recv_buf[sizeof(test_data)];
	LOG("%s: sceNetInetRecv %d 0x%x %d %d\n", __func__, accept_sock, recv_buf, sizeof(recv_buf), 0);
	int recv_state = sceNetInetRecv(accept_sock, recv_buf, sizeof(recv_buf), 0);
	if (recv_state < 0){
		LOG("%s: failed receiving data, 0x%x\n", __func__, recv_state);
		return;
	}

	if(recv_state != sizeof(test_data)){
		LOG("%s: not getting the full small transmission somehow\n", __func__);
		return;
	}
	if (memcmp(test_data, recv_buf, sizeof(test_data)) != 0){
		LOG("%s: bad data received\n", __func__);
		return;
	}

	LOG("%s: tcp data received\n", __func__);

	LOG("%s: sceNetInetClose %d\n", __func__, sock);
	sceNetInetClose(sock);
	LOG("%s: sceNetInetClose %d\n", __func__, accept_sock);
	sceNetInetClose(accept_sock);

	sceKernelWaitThreadEnd(tid, 0);
	sceKernelDeleteThread(tid);
}

void udp_send(){
	sceKernelDelayThread(1000000);

	LOG("%s: sceNetInetSocket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_DGRAM, 0);
	int sock = sceNetInetSocket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
		LOG("%s: failed creating socket, 0x%x\n", __func__, sock);
		return;
	}

	struct sockaddr_in addr = {0};
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(27016);
	addr.sin_addr.s_addr = sceNetInetInetAddr("127.0.0.1");

	LOG("%s: sceNetInetBind %d 0x%x %d\n", __func__, sock, &addr, sizeof(addr));
	int bind_result = sceNetInetBind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (bind_result < 0){
		LOG("%s: failed binding socket, 0x%x\n", __func__, bind_result);
		return;
	}

	struct sockaddr_in to_addr = {0};
	to_addr.sin_len = sizeof(to_addr);
	to_addr.sin_family = AF_INET;
	to_addr.sin_port = htons(27015);
	to_addr.sin_addr.s_addr = sceNetInetInetAddr("127.0.0.1");

	LOG("%s: sceNetInetSendto %d 0x%x %d 0x%x 0x%x %d\n", __func__, sock, test_data, sizeof(test_data), 0, &to_addr, sizeof(to_addr));
	int send_status = sceNetInetSendto(sock, test_data, sizeof(test_data), 0, (struct sockaddr*)&to_addr, sizeof(to_addr));
	if (send_status < 0){
		LOG("%s: failed sending, 0x%x\n", __func__, send_status);
		return;
	}

	sceKernelDelayThread(1000000);

	LOG("%s: sceNetInetClose %d\n", __func__, sock);
	sceNetInetClose(sock);
}

int udp_send_thread(SceSize args, void *argp){
	udp_send();
	return 0;
}

void test_udp(){
	LOG("%s: sceNetInetSocket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_DGRAM, 0);
	int sock = sceNetInetSocket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
		LOG("%s: failed creating socket, 0x%x\n", __func__, sock);
		return;
	}

	struct sockaddr_in addr = {0};
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(27015);
	addr.sin_addr.s_addr = sceNetInetInetAddr("127.0.0.1");

	LOG("%s: sceNetInetBind %d 0x%x %d\n", __func__, sock, &addr, sizeof(addr));
	int bind_result = sceNetInetBind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (bind_result < 0){
		LOG("%s: failed binding socket, 0x%x\n", __func__, bind_result);
		return;
	}

	int tid = sceKernelCreateThread("udp send thread", udp_send_thread, 0x18, 0x10000, 0, NULL);
	if (tid < 0){
		LOG("%s: failed creating thread, 0x%x\n", __func__, tid);
		return;
	}
	sceKernelStartThread(tid, 0, NULL);

	struct sockaddr_in from_addr = {0};
	char recv_buf[sizeof(test_data)];
	socklen_t addr_size = sizeof(from_addr);
	LOG("%s: sceNetInetRecvfrom %d 0x%x %d 0x%x 0x%x %d\n", __func__, sock, recv_buf, sizeof(test_data), 0, &from_addr, sizeof(from_addr));
	int recv_status = sceNetInetRecvfrom(sock, recv_buf, sizeof(test_data), 0, (struct sockaddr *)&from_addr, &addr_size);
	if (recv_status < 0){
		LOG("%s: failed receiving, 0x%x\n", __func__, recv_status);
		return;
	}

	sceKernelDelayThread(1000000);

	if (recv_status != sizeof(test_data)){
		LOG("%s: bad received length\n", __func__);
		return;
	}
	if (memcmp(test_data, recv_buf, sizeof(test_data)) != 0){
		LOG("%s: bad received data\n", __func__);
		return;
	}
	if (from_addr.sin_port != htons(27016)){
		LOG("%s: bad receive port\n", __func__);
		return;
	}
	if (from_addr.sin_addr.s_addr != sceNetInetInetAddr("127.0.0.1")){
		LOG("%s: bad receive address\n", __func__);
		return;
	}
	LOG("%s: udp data received\n", __func__);

	LOG("%s: sceNetInetClose %d\n", __func__, sock);
	sceNetInetClose(sock);

	sceKernelWaitThreadEnd(tid, 0);
	sceKernelDeleteThread(tid);
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

	test_tcp();
	test_udp();
}

int test_thread(SceSize args, void *argp){
	test();
	return 0;
}

int main(void) {
	INIT_LOG();
	SetupCallbacks();

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
