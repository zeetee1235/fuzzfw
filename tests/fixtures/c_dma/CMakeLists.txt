cmake_minimum_required(VERSION 3.20)
project(fuzzfw_c_dma_fixture C)

add_library(dma STATIC src/dma.c)
target_include_directories(dma PUBLIC include)
target_compile_features(dma PRIVATE c_std_11)
