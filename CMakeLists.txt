cmake_minimum_required(VERSION 3.25)
project(tsa_client)

set(CMAKE_CXX_STANDARD 20)

add_executable(tsa_client main.cpp)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
target_link_libraries(tsa_client OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)
