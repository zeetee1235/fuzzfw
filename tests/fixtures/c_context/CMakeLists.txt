cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_context_fixture C)

add_library(parser_context STATIC src/context.c)
target_include_directories(parser_context PUBLIC include)
target_compile_features(parser_context PRIVATE c_std_11)
