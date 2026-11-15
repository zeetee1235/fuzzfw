cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_state_fixture C)

add_library(state STATIC src/state.c)
target_include_directories(state PUBLIC include)
target_compile_features(state PRIVATE c_std_11)
