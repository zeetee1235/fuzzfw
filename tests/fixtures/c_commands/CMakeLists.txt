cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_commands_fixture C)

add_library(commands STATIC src/commands.c)
target_include_directories(commands PUBLIC include)
target_compile_features(commands PRIVATE c_std_11)
