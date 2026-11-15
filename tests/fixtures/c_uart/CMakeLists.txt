cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_uart_fixture C)

add_library(uart_fixture STATIC src/uart.c)
target_include_directories(uart_fixture PUBLIC include)
target_compile_features(uart_fixture PRIVATE c_std_11)
