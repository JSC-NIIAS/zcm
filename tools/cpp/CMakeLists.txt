cmake_minimum_required(VERSION 2.8)

project(zcm_tools)
set (CMAKE_CXX_FLAGS "-std=c++11 -pthread -lelf -ldl -O2 ${CMAKE_CXX_FLAGS}")

add_subdirectory(util)
add_subdirectory(bridge)
add_subdirectory(indexer)
add_subdirectory(logger)
add_subdirectory(logplayer)
add_subdirectory(repeater)
add_subdirectory(spy-lite)
add_subdirectory(spy-peek)
add_subdirectory(transcoder)
