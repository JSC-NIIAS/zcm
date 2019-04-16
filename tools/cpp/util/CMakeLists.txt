cmake_minimum_required(VERSION 2.8)

project(zcm_tools_util)
set (CMAKE_CXX_FLAGS "-std=c++11 -ldl -lelf -O2 ${CMAKE_CXX_FLAGS}")

add_library(${PROJECT_NAME} SHARED
    SymtabElf.cpp
    TranscoderPluginDb.cpp
    TypeDb.cpp)

include_directories(../../../
    ../)

link_directories(${CMAKE_SOURCE_DIR}/build)

target_link_libraries(${PROJECT_NAME} zcm)

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)
