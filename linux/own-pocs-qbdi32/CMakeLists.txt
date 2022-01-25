cmake_minimum_required (VERSION 3.2)
project(QBDITemplate)

find_package(QBDIX86 REQUIRED)

FILE(GLOB MyCSources src/*.c)
enable_language(ASM)
set_property(SOURCE src/ctx_32to64.s PROPERTY LANGUAGE ASM)

add_executable(qbdi_template qbdi_template.c ${MyCSources} src/ctx_32to64.s)
set_target_properties(qbdi_template PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

# Easier to build using QBDI static library on Windows
if(MSVC)
    target_link_libraries(qbdi_template QBDI::X86::QBDI_static)
else()
    target_link_libraries(qbdi_template QBDI::X86::QBDI)
endif()
