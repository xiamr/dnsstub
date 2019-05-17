cmake_minimum_required(VERSION 3.10)
project(dnsstub)

file(STRINGS "VERSION" DNSSTUB_VERSION)
set(DNSSTUB_AUTHOR "MiaoRen Xia")

set(CMAKE_CXX_STANDARD 17)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb3")
    add_compile_options(-Wall -Wextra)
endif ()


set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if (DEFINED ENV{LIBRARY_PATH})
    string(REPLACE ":" ";" LIBRARY_DIRS $ENV{LIBRARY_PATH})
endif ()
if (DEFINED ENV{CPATH})
    string(REPLACE ":" ";" CPATH_DIRS $ENV{CPATH})
endif ()
if (DEFINED ENV{C_INCLUDE_PATH})
    string(REPLACE ":" ";" C_INCLUDE_DIRS $ENV{C_INCLUDE_PATH})
endif ()
if (DEFINED ENV{CPLUS_INCLUDE_PATH})
    string(REPLACE ":" ";" CPLUS_INCLUDE_DIRS $ENV{CPLUS_INCLUDE_PATH})
endif ()
set(DEFAULT_INCLUDE_DIRS "/usr/include;/usr/local/include")

find_library(HAVE_LIBRT rt)
if (NOT DEFINED HAVE_LIBRT)
    message(FATAL_ERROR "rt library not found")
endif ()
link_libraries(rt)

# Boost
set(BOOST_INCLUDEDIR ${CPATH_DIRS} ${C_INCLUDE_DIRS} ${CPLUS_INCLUDE_DIRS} ${DEFAULT_INCLUDE_DIRS})
set(BOOST_LIBRARYDIR ${LIBRARY_DIRS})
find_package(Boost 1.67 REQUIRED COMPONENTS program_options log log_setup container)
include_directories(${Boost_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES})
link_libraries(boost_program_options boost_log boost_log_setup boost_container boost_thread)

add_definitions(-DBOOST_LOG_DYN_LINK)

option(ENABLE_XML "use xml configuration format based on pugixml" OFF)
if (ENABLE_XML)
    # pugixml
    find_path(PUGIXML_INCLUDES pugixml.hpp HITS ${CPATH_DIRS} ${C_INCLUDE_DIRS} ${CPLUS_INCLUDE_DIRS} ${DEFAULT_INCLUDE_DIRS})
    if (NOT PUGIXML_INCLUDES)
        message(FATAL_ERROR "xml parse library < pugixml header file> not found")
    endif ()
    include_directories(${PUGIXML_INCLUDES})

    find_library(LIBPUGIXML pugixml PATHS ${LIBRARY_DIRS})
    if (NOT LIBPUGIXML)
        message(FATAL_ERROR "xml parse library < pugixml library file> not found")
    endif ()
    link_libraries(${LIBPUGIXML})
endif ()


include_directories(${PROJECT_BINARY_DIR})
string(TIMESTAMP CMAKE_CONFIGURE_TIME "%Y-%m-%d %H:%M:%S")
configure_file(config.h.cmake config.h)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(src)
