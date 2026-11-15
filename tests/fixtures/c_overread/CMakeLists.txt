cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_overread_fixture C)

add_library(overread STATIC src/overread.c)
target_include_directories(overread PUBLIC include)
target_compile_features(overread PRIVATE c_std_11)
