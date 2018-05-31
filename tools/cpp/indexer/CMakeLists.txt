cmake_minimum_required(VERSION 2.8)

project(indexer)

set(HEADERS IndexerPluginDb.hpp)
set(SOURCES IndexerPluginDb.cpp
    main.cpp)

include_directories(../../../
    ../)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(${PROJECT_NAME} libzcm.a)
#target_link_libraries(${PROJECT_NAME} libzcm.a libzcm_tools_util.a)

link_directories(../util)
