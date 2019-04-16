cmake_minimum_required(VERSION 2.8)

project(transcoder)

set (CMAKE_CXX_FLAGS "-std=c++11 -pthread -ldl -O2 ${CMAKE_CXX_FLAGS}")

set(SOURCES main.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

include_directories(../../../
    ../)

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

link_directories(${CMAKE_SOURCE_DIR}/build
                 ${CMAKE_SOURCE_DIR}/build/tools/cpp/util)
                 
target_link_libraries(${PROJECT_NAME} zcm libzcm_tools_util.a)
