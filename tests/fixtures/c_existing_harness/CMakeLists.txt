cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_existing_harness_fixture C)

add_library(existing_parser STATIC src/parser.c)
target_include_directories(existing_parser PUBLIC include)
target_compile_features(existing_parser PRIVATE c_std_11)
