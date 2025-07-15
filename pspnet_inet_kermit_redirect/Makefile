TARGET = pspnet_inet_kermit_redirect
OBJS = main.o hooking.o hen.o kermit.o kermit_import.o

CFLAGS = $(CFLAGS_EXTRA) -O2 -Os -G0 -Wall -fshort-wchar -fno-pic -mno-check-zero-division -fno-builtin -DDEBUG_LOG=1
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

BUILD_PRX = 1
PRX_EXPORTS = exports.exp

# use kernel libraries
USE_KERNEL_LIBS = 1

PSP_FW_VERSION=661

LDFLAGS = -nostartfiles

LIBS =

PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build_prx.mak
