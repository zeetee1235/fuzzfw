cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_hal_fixture C)

add_library(sensor STATIC src/sensor.c)
target_include_directories(sensor PUBLIC include)
target_compile_features(sensor PRIVATE c_std_11)
