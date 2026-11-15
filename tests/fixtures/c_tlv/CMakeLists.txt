cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_tlv_fixture C)

add_library(tlv_fixture STATIC src/tlv.c)
target_include_directories(tlv_fixture PUBLIC include)
target_compile_features(tlv_fixture PRIVATE c_std_11)
