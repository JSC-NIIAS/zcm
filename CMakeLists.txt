cmake_minimum_required(VERSION 2.8)

project(zcm C CXX)

set(${PROJECT_NAME}_DESCRIPTION "ZCM lib for ARM")
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_FLAGS "-std=c++11 -lzmq ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS "-std=c99 -lzmq ${CMAKE_C_FLAGS}")

option(CROSSCOMPILE "ARM crosscompil" OFF)

if(CROSSCOMPILE)
    include_directories(../../staging/usr/include)
endif(CROSSCOMPILE)

add_definitions(
    -DHAVE_ZMQ=1
    -D_LARGEFILE_SOURCE
    -D_FILE_OFFSET_BITS=64
    -DUSING_CPP
    -DUSING_OPT
    -DUSING_TRANS_INPROC
    -DUSING_TRANS_IPC
    -DUSING_TRANS_SERIAL
    -DUSING_TRANS_UDPM
    -DUSING_ZMQ
    -DENABLE_TYPENAME_HASHING)

add_library(${PROJECT_NAME} SHARED
    zcm/json/jsoncpp.cpp
    zcm/blocking.cpp
    zcm/eventlog.c
    zcm/nonblocking.c
    zcm/transport_registrar.c
    zcm/url.cpp
    zcm/zcm.c
    zcm/tools/IndexerPlugin.cpp
    zcm/transport/generic_serial_transport.c
    zcm/transport/transport_file.cpp
    zcm/transport/transport_inproc.cpp
    zcm/transport/transport_serial.cpp
    zcm/transport/transport_zmq_local.cpp
    zcm/transport/udpm/buffers.cpp
    zcm/transport/udpm/mempool.cpp
    zcm/transport/udpm/udpm.cpp
    zcm/transport/udpm/udpmsocket.cpp
    zcm/util/debug.cpp
    zcm/util/lockfile.cpp)

install(TARGETS ${PROJECT_NAME}
       ARCHIVE DESTINATION /usr/lib
       LIBRARY DESTINATION /usr/lib
       PUBLIC_HEADER DESTINATION /usr/include/zcm)

#find_library(ZCMLIB name zmq
#    PATHS
#    /usr/lib
#    /usr/lib64
#    /usr/local/lib)

#
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON
    PUBLIC_HEADER zcm/zcm.h
    zcm/zcm-cpp.hpp
    zcm/zcm-cpp-impl.hpp
    zcm/blocking.h
    zcm/eventlog.h
    zcm/nonblocking.h
    zcm/transport.h
    zcm/transport_registrar.h
    zcm/url.h
    zcm/zcm_coretypes.h
    zcm/zcm_private.h)

target_include_directories(${PROJECT_NAME} PRIVATE
    .
    zcm
    zcm/util
    zcm/json
    zcm/tools
    zcm/transport
    zcm/transport/udpm)

add_subdirectory(tools/cpp)
add_subdirectory(gen)

