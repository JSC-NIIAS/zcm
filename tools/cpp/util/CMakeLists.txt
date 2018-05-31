cmake_minimum_required(VERSION 2.8)

project(zcm_tools_util)
set (CMAKE_CXX_FLAGS "-std=c++11 -ldl -lelf -lzcm -O2 ${CMAKE_CXX_FLAGS}")
#set (CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS}")

add_library(${PROJECT_NAME} STATIC
    SymtabElf.cpp
    TranscoderPluginDb.cpp
    TypeDb.cpp)

include_directories(../../../
    ../)

#install(TARGETS ${PROJECT_NAME}
#       ARCHIVE DESTINATION /usr/lib
#       LIBRARY DESTINATION /usr/lib
#       PUBLIC_HEADER DESTINATION /usr/include/zcm)

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)
