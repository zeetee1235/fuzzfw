cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_unit_test_fixture C)

add_library(unit_test_fixture STATIC src/parser.c)
target_include_directories(unit_test_fixture PUBLIC include)
target_compile_features(unit_test_fixture PRIVATE c_std_11)
