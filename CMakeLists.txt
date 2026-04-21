cmake_minimum_required(VERSION 3.5)

project(ss-libuv C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Dependencies
find_package(OpenSSL REQUIRED)

# Try to find libuv
find_path(LIBUV_INCLUDE_DIR NAMES uv.h)
find_library(LIBUV_LIBRARY NAMES uv)

if(NOT LIBUV_INCLUDE_DIR OR NOT LIBUV_LIBRARY)
    if(WIN32)
        message(FATAL_ERROR "libuv not found. Please install it via vcpkg or set LIBUV_INCLUDE_DIR and LIBUV_LIBRARY.")
    else()
        message(WARNING "libuv not found by find_path/find_library. Falling back to default 'uv' name.")
        set(LIBUV_LIBRARY uv)
    endif()
endif()

# Source files
set(COMMON_SOURCES
    src/crypt.c
    src/handshake.c
    src/remote.c
    src/shadow.c
    src/utils.c
)

if(WIN32 OR CMAKE_SYSTEM_NAME MATCHES "MINGW")
    list(APPEND COMMON_SOURCES src/getopt.c)
endif()

add_executable(ssclient
    src/client.c
    src/localmain.c
    src/localser.c
    ${COMMON_SOURCES}
)

add_executable(ssserver
    src/server.c
    ${COMMON_SOURCES}
)

# Target configurations
foreach(target ssclient ssserver)
    if(LIBUV_INCLUDE_DIR)
        target_include_directories(${target} PRIVATE ${LIBUV_INCLUDE_DIR})
    endif()
    target_include_directories(${target} PRIVATE src)

    target_link_libraries(${target} PRIVATE ${LIBUV_LIBRARY} OpenSSL::SSL OpenSSL::Crypto)

    if(WIN32 OR CMAKE_SYSTEM_NAME MATCHES "MINGW")
        target_link_libraries(${target} PRIVATE ws2_32)
    else()
        target_compile_definitions(${target} PRIVATE HAVE_UNISTD_H)
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:-O0 -Wall -g -ggdb>)
    endif()
endforeach()
