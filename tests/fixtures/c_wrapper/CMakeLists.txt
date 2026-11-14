cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_wrapper_fixture C)

add_library(app STATIC src/app.c)
target_include_directories(app PUBLIC include)
target_compile_features(app PRIVATE c_std_11)
