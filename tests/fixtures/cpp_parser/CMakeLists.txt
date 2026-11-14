cmake_minimum_required(VERSION 3.20)
project(fuzzfw_cpp_parser_fixture CXX)

add_library(codec STATIC src/codec.cpp)
target_include_directories(codec PUBLIC include)
target_compile_features(codec PRIVATE cxx_std_17)
