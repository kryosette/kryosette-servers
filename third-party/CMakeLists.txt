cmake_minimum_required(VERSION 3.10)
project(smemset VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(POLICY CMP0079)
    cmake_policy(SET CMP0079 NEW)
endif()

add_library(smemset 
    smemset.c
)

target_include_directories(smemset
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(smemset PRIVATE 
    -Wall
    -Wextra
    -Werror
    -O2
)

set_target_properties(smemset PROPERTIES
    PUBLIC_HEADER "include/smemset.h"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

install(TARGETS smemset
    EXPORT smemset-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

install(EXPORT smemset-targets
    FILE smemset-config.cmake
    NAMESPACE smemset::
    DESTINATION lib/cmake/smemset
)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()