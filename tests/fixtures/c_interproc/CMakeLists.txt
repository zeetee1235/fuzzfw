cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_interproc_fixture C)

add_library(interproc STATIC src/interproc.c)
target_include_directories(interproc PUBLIC include)
target_compile_features(interproc PRIVATE c_std_11)
