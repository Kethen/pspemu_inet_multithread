    .set noreorder

#include "pspimport.s"

	IMPORT_START "sceKermit_driver",0x00010011
	IMPORT_FUNC  "sceKermit_driver",0x36666181,sceKermitSendRequest661

