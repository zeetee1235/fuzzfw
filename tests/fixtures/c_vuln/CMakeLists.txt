cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_parser_fixture C)

add_library(parser STATIC src/parser.c)
target_include_directories(parser PUBLIC include)
target_compile_features(parser PRIVATE c_std_11)
