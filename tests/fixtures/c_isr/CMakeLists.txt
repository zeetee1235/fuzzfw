cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_isr_fixture C)

add_library(isr STATIC src/isr.c)
target_include_directories(isr PUBLIC include)
target_compile_features(isr PRIVATE c_std_11)
