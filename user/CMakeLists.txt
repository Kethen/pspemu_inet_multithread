cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(NoPspEmuDrm_user)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -O3 -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")


add_executable(pspemu_inet_multithread
	main.c
)

target_link_libraries(pspemu_inet_multithread
	taihen_stub
	SceLibc_stub_weak
	SceLibKernel_stub
	SceKernelModulemgr_stub 
	SceIofilemgr_stub
	SceKernelThreadMgr_stub
)



set_target_properties(pspemu_inet_multithread
  PROPERTIES LINK_FLAGS "-nostdlib"
)

vita_create_self(pspemu_inet_multithread.suprx pspemu_inet_multithread CONFIG exports.yml UNSAFE)
vita_create_stubs(stubs pspemu_inet_multithread ${CMAKE_SOURCE_DIR}/exports.yml)
