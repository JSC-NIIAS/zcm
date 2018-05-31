cmake_minimum_required(VERSION 2.8)

project(repeater)

set(SOURCES main.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

include_directories(../../../
    ../)

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

#target_link_libraries(${PROJECT_NAME} libzcm.a)

target_link_libraries(${PROJECT_NAME} libzcm.a libzcm_tools_util.a)
