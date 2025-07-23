cmake_minimum_required(VERSION 3.31)
project(hmac_with_c)

set(CMAKE_CXX_STANDARD 11)

add_executable(hmac_with_c main.cpp)

target_link_libraries(
        hmac_with_c
        #ssl
        crypto
)
