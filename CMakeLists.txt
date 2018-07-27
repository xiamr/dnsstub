cmake_minimum_required(VERSION 3.10)
project(dnsstub)

set(CMAKE_CXX_STANDARD 14)
link_libraries(rt)

add_executable(dnsstub main.cpp)