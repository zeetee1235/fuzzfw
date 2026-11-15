cmake_minimum_required(VERSION 3.20)
project(fuzzfw_cpp_context_fixture CXX)

add_library(context_parser STATIC src/parser.cpp)
target_include_directories(context_parser PUBLIC include)
target_compile_features(context_parser PRIVATE cxx_std_17)
