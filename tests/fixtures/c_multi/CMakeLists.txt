cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_multi_fixture C)

add_library(multi STATIC src/multi.c)
target_include_directories(multi PUBLIC include)
target_compile_features(multi PRIVATE c_std_11)
