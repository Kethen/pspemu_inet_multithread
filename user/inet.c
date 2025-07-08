#include <vitasdk.h>

#include "log.h"
#include "kermit.h"

int handle_inet_request(SceKermitRequest *request){
	LOG("%s: 0x%x not implemented\n", __func__, request->cmd);
	return 0;
}

