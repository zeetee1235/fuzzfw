cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_msan_fixture C)

add_library(msan_fixture STATIC src/msan.c)
target_include_directories(msan_fixture PUBLIC include)
target_compile_features(msan_fixture PRIVATE c_std_11)
