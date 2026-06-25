cmake_minimum_required(VERSION 4.1)
project(tsa_client)

set(CMAKE_CXX_STANDARD 20)

add_executable(tsa_client main.cpp)
target_link_libraries(tsa_client ssl crypto)
