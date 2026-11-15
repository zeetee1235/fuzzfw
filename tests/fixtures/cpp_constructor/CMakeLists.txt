cmake_minimum_required(VERSION 3.20)
project(fuzzfw_cpp_constructor_fixture CXX)

add_library(cpp_constructor STATIC src/parser.cpp)
target_include_directories(cpp_constructor PUBLIC include)
target_compile_features(cpp_constructor PRIVATE cxx_std_17)
