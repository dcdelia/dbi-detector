cmake_minimum_required (VERSION 3.2)
project(QBDITemplate)

find_package(QBDIX86_64 REQUIRED)

#include_directories(inc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -D_FORTIFY_SOURCE=2 -fno-plt -Wl,-z,relro,-z,now -fPIC -pie -Wall -pedantic -fno-omit-frame-pointer -fstack-protector-all -ftrapv -Wstrict-prototypes -mfsgsbase")
FILE(GLOB MyCSources *.c)
add_executable(qbdi_template ${MyCSources})

set(CMAKE_EXE_LINKER_FLAGS "-Wl,-z,relro,-z,now -pie -lm -ldl" ${CMAKE_EXE_LINKER_FLAGS})
target_link_libraries(qbdi_template QBDI::X86_64::QBDI dl m)
