cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_sequence_fixture C)

add_library(sequence STATIC src/sequence.c)
target_include_directories(sequence PUBLIC include)
target_compile_features(sequence PRIVATE c_std_11)
