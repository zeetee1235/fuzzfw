cmake_minimum_required(VERSION 3.20)
project(fuzzfw_cpp_msan_fixture CXX)

add_library(cpp_msan_fixture STATIC src/msan.cpp)
target_include_directories(cpp_msan_fixture PUBLIC include)
target_compile_features(cpp_msan_fixture PRIVATE cxx_std_17)
