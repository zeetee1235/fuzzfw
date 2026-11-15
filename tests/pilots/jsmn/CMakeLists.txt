cmake_minimum_required(VERSION 3.20)
project(fuzzfw_jsmn_pilot C)

add_library(jsmn STATIC src/jsmn_impl.c)
target_include_directories(jsmn PUBLIC include)
target_compile_features(jsmn PRIVATE c_std_11)
