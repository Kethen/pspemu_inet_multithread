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

PSP_MODULE_INFO("inet test", 0x1000, 1, 1);
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
		LOG("%s: failed creating socket, 0x%x 0x%x\n", __func__, sock, sceNetInetGetErrno());
		return;
	}

	struct sockaddr_in addr = {0};
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(27015);
	addr.sin_addr.s_addr = sceNetInetInetAddr("127.0.0.1");

	int sock_opt = 1;
	LOG("%s: sceNetInetSetsockopt %d 0x%x 0x%x 0x%x %d\n", __func__, sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, sizeof(sock_opt));
	int set_sockopt_status = sceNetInetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, (socklen_t)sizeof(sock_opt));
	if (set_sockopt_status < 0){
		LOG("%s: failed setting tcp nodelay socket option, 0x%x 0x%x\n", __func__, set_sockopt_status, sceNetInetGetErrno());
		return;
	}

	sock_opt = 1;
	LOG("%s: sceNetInetSetsockopt %d 0x%x 0x%x 0x%x %d\n", __func__, sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, sizeof(sock_opt));
	set_sockopt_status = sceNetInetSetsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, (socklen_t)sizeof(sock_opt));
	if (set_sockopt_status < 0){
		LOG("%s: failed setting keepalive socket option, 0x%x 0x%x\n", __func__, set_sockopt_status, sceNetInetGetErrno());
		return;
	}

	socklen_t sockopt_len = sizeof(int);
	LOG("%s: sceNetInetGetsockopt %d 0x%x 0x%x 0x%x %d\n", __func__, sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, sizeof(sock_opt));
	int get_sockopt_status = sceNetInetGetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &sock_opt, &sockopt_len);
	if (get_sockopt_status < 0){
		LOG("%s: failed getting socket option, 0x%x 0x%x\n", __func__, get_sockopt_status, sceNetInetGetErrno());
		return;
	}
	if (!sock_opt){
		LOG("%s: tcp nodelay socket option was not set properly, 0x%x\n", __func__, sock_opt);
		return;
	}

	sockopt_len = sizeof(int);
	LOG("%s: sceNetInetGetsockopt %d 0x%x 0x%x 0x%x %d\n", __func__, sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, sizeof(sock_opt));
	get_sockopt_status = sceNetInetGetsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &sock_opt, &sockopt_len);
	if (get_sockopt_status < 0){
		LOG("%s: failed getting socket option, 0x%x 0x%x\n", __func__, get_sockopt_status, sceNetInetGetErrno());
		return;
	}
	if (!sock_opt){
		LOG("%s: keepalive socket option was not set properly, 0x%x\n", __func__, sock_opt);
		return;
	}

	LOG("%s: sceNetInetConnect %d, 0x%x, %d\n", __func__, sock, &addr, sizeof(addr));
	int connect_status = sceNetInetConnect(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (connect_status < 0){
		LOG("%s: failed connecting, 0x%x 0x%x\n", __func__, connect_status, sceNetInetGetErrno());
		return;
	}

	LOG("%s: sceNetInetSend %d 0x%x %d %d\n", __func__, sock, test_data, sizeof(test_data), 0);
	int send_status = sceNetInetSend(sock, test_data, sizeof(test_data), 0);
	if (send_status < 0){
		LOG("%s: failed sending, 0x%x 0x%x\n", __func__, send_status, sceNetInetGetErrno());
		return;
	}
	if (send_status != sizeof(test_data)){
		LOG("%s: sent %d bytes, expected %d\n", __func__, send_status, sizeof(test_data));
	}

	sceKernelDelayThread(1000000 * 2);

	struct sockaddr_in peer_addr = {0};
	socklen_t peer_addr_len = sizeof(peer_addr);
	LOG("%s: sceNetInetGetpeername %d 0x%x 0x%x\n", __func__, sock, &peer_addr, &peer_addr_len);
	sceNetInetGetpeername(sock, (struct sockaddr*)&peer_addr, &peer_addr_len);
	if (peer_addr.sin_addr.s_addr != sceNetInetInetAddr("127.0.0.1")){
		LOG("%s: bad peer addr\n");
	}
	if (peer_addr.sin_port != htons(27015)){
		LOG("%s: bad peer port\n");
	}

	LOG("%s: sceNetInetClose %d\n", __func__, sock);
	sceNetInetClose(sock);
}

int tcp_send_thread(SceSize args, void *argp){
	tcp_send();
	return 0;
}

void test_tcp(){
	uint32_t *sceNetInetSocket_func = (uint32_t *)sceNetInetSocket;
	LOG("%s: sceNetInetSocket instructions 0x%x 0x%x\n", __func__, sceNetInetSocket_func[0], sceNetInetSocket_func[1]);
	#undef GET_JUMP_TARGET

	LOG("%s: sceNetInetSocket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_STREAM, 0);
	int sock = sceNetInetSocket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0){
		LOG("%s: failed creating socket, 0x%x 0x%x\n", __func__, sock, sceNetInetGetErrno());
		return;
	}

	struct sockaddr_in addr = {0};
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(27015);
	addr.sin_addr.s_addr = sceNetInetInetAddr("127.0.0.1");
	LOG("%s: s_addr 0x%x\n", __func__, addr.sin_addr.s_addr);

	LOG("%s: sceNetInetBind %d 0x%x %d\n", __func__, sock, &addr, sizeof(addr));
	int bind_result = sceNetInetBind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (bind_result < 0){
		LOG("%s: failed binding socket, 0x%x 0x%x\n", __func__, bind_result, sceNetInetGetErrno());
		return;
	}

	LOG("%s: sceNetInetListen %d %d\n", __func__, sock, 100);
	int listen_result = sceNetInetListen(sock, 100);
	if (listen_result < 0){
		LOG("%s: failed setting up listen, 0x%x 0x%x\n", __func__, listen_result, sceNetInetGetErrno());
		return;
	}

	struct sockaddr_in self_addr = {0};
	socklen_t self_addr_len = sizeof(self_addr);
	LOG("%s: sceNetInetGetsockname %d 0x%x 0x%x\n", __func__, sock, &self_addr, &self_addr_len);
	sceNetInetGetsockname(sock, (struct sockaddr*)&self_addr, &self_addr_len);
	if (self_addr.sin_addr.s_addr != sceNetInetInetAddr("127.0.0.1")){
		LOG("%s: bad self addr\n");
	}
	if (self_addr.sin_port != htons(27015)){
		LOG("%s: bad self port\n");
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
		LOG("%s: failed accepting connection, 0x%x 0x%x\n", __func__, accept_sock, sceNetInetGetErrno());
		return;
	}

	char recv_buf[sizeof(test_data)];
	LOG("%s: sceNetInetRecv %d 0x%x %d %d\n", __func__, accept_sock, recv_buf, sizeof(recv_buf), 0);
	int recv_state = sceNetInetRecv(accept_sock, recv_buf, sizeof(recv_buf), 0);
	if (recv_state < 0){
		LOG("%s: failed receiving data, 0x%x 0x%x\n", __func__, recv_state, sceNetInetGetErrno());
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

void udp_send(){
	sceKernelDelayThread(1000000);

	LOG("%s: sceNetInetSocket 0x%x 0x%x 0x%x\n", __func__, AF_INET, SOCK_DGRAM, 0);
	int sock = sceNetInetSocket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
		LOG("%s: failed creating socket, 0x%x 0x%x\n", __func__, sock, sceNetInetGetErrno());
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
		LOG("%s: failed binding socket, 0x%x 0x%x\n", __func__, bind_result, sceNetInetGetErrno());
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
		LOG("%s: failed sending, 0x%x 0x%x\n", __func__, send_status, sceNetInetGetErrno());
		return;
	}

	sceKernelDelayThread(1000000);

	struct SceNetMsghdr msg = {0};
	msg.msg_name = &to_addr;
	msg.msg_namelen = sizeof(to_addr);
	uint32_t send_buf[sizeof(test_data)] = {0};
	struct SceNetIovec msg_iov[sizeof(test_data)] = {0};
	for (int i = 0;i < sizeof(test_data);i++){
		send_buf[i] = test_data[i];
		msg_iov[i].iov_base = &send_buf[i];
		msg_iov[i].iov_len = 1;
	}
	msg.msg_iov = msg_iov;
	msg.msg_iovlen = sizeof(test_data);
	LOG("%s: sceNetInetSendmsg %d 0x%x 0x%x\n", __func__, sock, &msg, 0);
	send_status = sceNetInetSendmsg(sock, (void *)&msg, 0);
	if (send_status < 0){
		LOG("%s: failed sending as message, 0x%x 0x%x\n", __func__, send_status, sceNetInetGetErrno());
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
		LOG("%s: failed creating socket, 0x%x 0x%x\n", __func__, sock, sceNetInetGetErrno());
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
		LOG("%s: failed binding socket, 0x%x 0x%x\n", __func__, bind_result, sceNetInetGetErrno());
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
		LOG("%s: failed receiving, 0x%x 0x%x\n", __func__, recv_status, sceNetInetGetErrno());
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

	sceKernelDelayThread(1000000);

	struct SceNetMsghdr msg = {0};
	memset(&from_addr, 0, sizeof(from_addr));
	msg.msg_name = &from_addr;
	msg.msg_namelen = sizeof(from_addr);

	uint32_t msg_recv_buf[sizeof(test_data)] = {0};
	struct SceNetIovec msg_iov[sizeof(test_data)] = {0};
	for (int i = 0;i < sizeof(test_data);i++){
		msg_iov[i].iov_base = &msg_recv_buf[i];
		msg_iov[i].iov_len = 1;
	}
	msg.msg_iov = msg_iov;
	msg.msg_iovlen = sizeof(test_data);

	recv_status = sceNetInetRecvmsg(sock, (void *)&msg, 0);
	if (recv_status < 0){
		LOG("%s: failed receiving as message, 0x%x 0x%x\n", __func__, recv_status, sceNetInetGetErrno());
		return;
	}
	if (from_addr.sin_port != htons(27016)){
		LOG("%s: bad receive port when receiving as message\n", __func__);
		return;
	}
	if (from_addr.sin_addr.s_addr != sceNetInetInetAddr("127.0.0.1")){
		LOG("%s: bad receive address when receiving as message\n", __func__);
		return;
	}
	for (int i = 0;i < sizeof(test_data);i++){
		if (msg_recv_buf[i] != test_data[i]){
			LOG("%s: bad recevied data when receiving as message\n", __func__);
			return;
		}
	}
	LOG("%s: udp data received as message\n", __func__);

	sceKernelDelayThread(1000000);

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

	uint8_t local_mac[8] = {0};
	sceNetGetLocalEtherAddr(local_mac);
	LOG("%s: local mac is %x:%x:%x:%x:%x:%x\n", __func__, local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);

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
