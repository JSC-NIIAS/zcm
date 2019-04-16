cmake_minimum_required(VERSION 2.8)

project(logger)

set(SOURCES main.cpp)
set(HEADERS platform.hpp)

include_directories(../../../
    ../)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

link_directories(${CMAKE_SOURCE_DIR}/build/util
                 ${CMAKE_SOURCE_DIR}/build/)

target_link_libraries(${PROJECT_NAME} zcm zcm_tools_util)
