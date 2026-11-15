cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_command_table_fixture C)

add_library(command_table STATIC src/command_table.c)
target_include_directories(command_table PUBLIC include)
target_compile_features(command_table PRIVATE c_std_11)
