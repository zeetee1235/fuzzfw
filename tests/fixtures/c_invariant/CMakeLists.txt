cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_invariant_fixture C)

add_library(invariant STATIC src/invariant.c)
target_include_directories(invariant PUBLIC include)
target_compile_features(invariant PRIVATE c_std_11)
