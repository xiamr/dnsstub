cmake_minimum_required(VERSION 3.10)
project(dnsstub)

set(CMAKE_CXX_STANDARD 14)
find_library(HAVE_LIBRT rt)
if (NOT DEFINED HAVE_LIBRT)
    message(SEND_ERROR "rt library not found")
endif ()
link_libraries(rt)

add_executable(dnsstub main.cpp)