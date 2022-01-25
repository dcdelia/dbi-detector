cmake_minimum_required (VERSION 3.2)
project(QBDITemplate)

find_package(QBDIX86_64 REQUIRED)

#include_directories(inc)
FILE(GLOB MyCSources src/*.c)
add_executable(qbdi_template qbdi_template.c ${MyCSources})

# Easier to build using QBDI static library on Windows
if(MSVC)
    target_link_libraries(qbdi_template QBDI::X86_64::QBDI_static)
else()
    target_link_libraries(qbdi_template QBDI::X86_64::QBDI)
endif()
