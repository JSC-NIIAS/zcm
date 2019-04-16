cmake_minimum_required(VERSION 2.8)

project(spy-lite)

set(SOURCES Debug.cpp
    MsgDisplay.cpp
    MsgInfo.cpp
    main.cpp)
set(HEADERS Common.hpp
    Debug.hpp
    MsgDisplay.hpp
    MsgInfo.hpp
    ExpiringQueue.hpp)

include_directories(../../../
    ../)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(${PROJECT_NAME} zcm zcm_tools_util)

link_directories(${CMAKE_SOURCE_DIR}/build
                 ${CMAKE_SOURCE_DIR}/build/tools/cpp/util)
