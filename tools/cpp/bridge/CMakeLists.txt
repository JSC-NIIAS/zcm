cmake_minimum_required(VERSION 2.8)

project(bridge)

set (CMAKE_CXX_FLAGS "-std=c++11 -pthread -ldl -lzcm_tools_util -lzcm ${CMAKE_CXX_FLAGS}")

set(SOURCES main.cpp)

include_directories(../../../
    ../)

add_executable(${PROJECT_NAME} ${SOURCES})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(${PROJECT_NAME} libzcm.a libzcm_tools_util.a)

#link_directories(util)
