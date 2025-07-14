#include <pspsdk.h>

#include <string.h>

#include "log.h"
#include "hen.h"
#include "hooking.h"

PSP_MODULE_INFO("pspnet_inet_kermit_redirect", PSP_MODULE_KERNEL, 1, 0);

STMOD_HANDLER last_handler = NULL;

int apply_patch(SceModule2 *mod){
	if (strcmp(mod->modname, "sceNetInet_Library") == 0){
		#define STR(s) #s
		#define MAKE_FUNCTION_REF(_name, _nid) \
			u32 _name##Ref = sctrlHENFindFunction("sceNetInet_Library", "sceNetInet", _nid); \
			LOG("%s: %s ref 0x%x\n", __func__, STR(_name), _name##Ref);

		MAKE_FUNCTION_REF(sceNetInetSocket, 0x8B7B220F);
		MAKE_FUNCTION_REF(sceNetInetBind, 0x1A33F9AE);
		MAKE_FUNCTION_REF(sceNetInetListen, 0xD10A1A7A);
		MAKE_FUNCTION_REF(sceNetInetAccept, 0xDB094E1B);
		MAKE_FUNCTION_REF(sceNetInetConnect, 0x410B34AA);
		MAKE_FUNCTION_REF(sceNetInetSetsockopt, 0x2FE71FE7);
		MAKE_FUNCTION_REF(sceNetInetGetsockopt, 0x4A114C7C);
		MAKE_FUNCTION_REF(sceNetInetGetsockname, 0x162E6FD5);
		MAKE_FUNCTION_REF(sceNetInetGetpeername, 0xE247B6D6);
		MAKE_FUNCTION_REF(sceNetInetSend, 0x7AA671BC);
		MAKE_FUNCTION_REF(sceNetInetSendto, 0x05038FC7);
		MAKE_FUNCTION_REF(sceNetInetSendmsg, 0x774E36F4);
		MAKE_FUNCTION_REF(sceNetInetRecv, 0xCDA85C99);
		MAKE_FUNCTION_REF(sceNetInetRecvfrom, 0xC91142E4);
		MAKE_FUNCTION_REF(sceNetInetRecvmsg, 0xEECE61D2);
		MAKE_FUNCTION_REF(sceNetInetClose, 0x8D7284EA);
		MAKE_FUNCTION_REF(sceNetInetPoll, 0x5BE8D595);
		MAKE_FUNCTION_REF(sceNetInetSelect, 0x5BE8D595);

		#undef STR
		#undef MAKE_FUNCTION_REF
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
