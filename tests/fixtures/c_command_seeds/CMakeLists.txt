cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_command_seeds_fixture C)

add_library(command_seeds STATIC src/command_seeds.c)
target_include_directories(command_seeds PUBLIC include)
target_compile_features(command_seeds PRIVATE c_std_11)
