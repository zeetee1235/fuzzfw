cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_output_fixture C)

add_library(output STATIC src/output.c)
target_include_directories(output PUBLIC include)
target_compile_features(output PRIVATE c_std_11)
