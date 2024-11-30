cmake_minimum_required(VERSION 3.28)
project(socks5_async C)

set(CMAKE_C_STANDARD 23)

add_executable(socks5_async main.c
        queue.c
        queue.h
        task.h)
target_link_libraries(socks5_async pthread)
