cmake_minimum_required(VERSION 2.8)

project(logplayer)

set(SOURCES main.cpp)

include_directories(../../../
    ../)

add_executable(${PROJECT_NAME} ${SOURCES})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

link_directories(${CMAKE_SOURCE_DIR}/build
                 ${CMAKE_SOURCE_DIR}/build/tools/cpp/util)
                 
target_link_libraries(${PROJECT_NAME} zcm zcm_tools_util)
