cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_rtos_fixture C)

add_library(rtos STATIC src/rtos.c)
target_include_directories(rtos PUBLIC include)
target_compile_features(rtos PRIVATE c_std_11)
