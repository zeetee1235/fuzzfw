cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_network_fixture C)

add_library(network_fixture STATIC src/network.c)
target_include_directories(network_fixture PUBLIC include)
target_compile_features(network_fixture PRIVATE c_std_11)
