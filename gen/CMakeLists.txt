cmake_minimum_required(VERSION 2.8)

project(zcm-gen)

set(HEADERS Common.hpp
    GetOpt.hpp
    ZCMGen.hpp
    tokenize.h
    version.h
    emit/Emit.hpp
    emit/Emitter.hpp)

set(SOURCES
    emit/EmitC.cpp
    emit/EmitCpp.cpp
    emit/EmitJava.cpp
    emit/EmitNode.cpp
    emit/EmitPython.cpp
    emit/Emitter.cpp
    tokenize.c
    GetOpt.cpp
    ZCMGen.cpp
    Main.cpp)

include_directories(../)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

set_target_properties(${PROJECT_NAME}
                      PROPERTIES POSITION_INDEPENDENT_CODE ON)


