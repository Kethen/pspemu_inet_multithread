TARGET = inet_test
OBJS = main.o

INCDIR = 
CFLAGS = -O2 -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

LIBDIR =
LDFLAGS =

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = inet test

PSP_LARGE_MEMORY = 0

LIBS = -lpsppower

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
