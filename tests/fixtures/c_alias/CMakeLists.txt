cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_alias_fixture C)

add_library(alias_fixture STATIC src/alias.c)
target_include_directories(alias_fixture PUBLIC include)
target_compile_features(alias_fixture PRIVATE c_std_11)
