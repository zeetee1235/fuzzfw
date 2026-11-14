# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 fuzzfw contributors
cmake_minimum_required(VERSION 3.20)
project(fuzzfw-analyzers CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Native analyzers use Clang/LLVM only as read-only libraries. They never
# transform user code. Prefer the standard CMake package + component libraries
# (Debian/Ubuntu), then fall back to shared libclang-cpp (Fedora/RHEL).
option(FUZZFW_FORCE_SHARED_CLANG "Force the shared libclang-cpp layout" OFF)
set(FUZZFW_CLANG_COMPONENTS OFF)
if(NOT FUZZFW_FORCE_SHARED_CLANG)
  find_package(LLVM CONFIG QUIET)
  find_package(Clang CONFIG QUIET)
  if(LLVM_FOUND AND Clang_FOUND AND TARGET clangTooling)
    set(FUZZFW_CLANG_COMPONENTS ON)
    set(LLVM_INCLUDE_DIR ${LLVM_INCLUDE_DIRS})
    set(CLANG_INCLUDE_DIR ${CLANG_INCLUDE_DIRS})
  endif()
endif()

if(NOT FUZZFW_CLANG_COMPONENTS)
find_path(LLVM_INCLUDE_DIR
  NAMES llvm/IR/LLVMContext.h
  HINTS /usr/lib64/llvm22/include /usr/lib/llvm-*/include /usr/include)
find_path(CLANG_INCLUDE_DIR
  NAMES clang/Tooling/Tooling.h
  HINTS /usr/lib64/llvm22/include /usr/lib/llvm-*/include /usr/include)

find_library(CLANG_CPP_LIBRARY
  NAMES clang-cpp
  HINTS /usr/lib64/llvm22/lib64 /usr/lib/llvm-*/lib /usr/lib64 /usr/lib)
find_library(LLVM_LIBRARY
  NAMES LLVM
  HINTS /usr/lib64/llvm22/lib64 /usr/lib/llvm-*/lib /usr/lib64 /usr/lib)

if(NOT LLVM_INCLUDE_DIR OR NOT CLANG_INCLUDE_DIR)
  message(FATAL_ERROR "LLVM/Clang development headers not found. Install clang-devel/llvm-devel or set LLVM_INCLUDE_DIR and CLANG_INCLUDE_DIR.")
endif()
if(NOT CLANG_CPP_LIBRARY OR NOT LLVM_LIBRARY)
  message(FATAL_ERROR "libclang-cpp/libLLVM not found. Set CLANG_CPP_LIBRARY and LLVM_LIBRARY.")
endif()
endif()

message(STATUS "LLVM headers: ${LLVM_INCLUDE_DIR}")
message(STATUS "Clang headers: ${CLANG_INCLUDE_DIR}")
message(STATUS "clang-cpp: ${CLANG_CPP_LIBRARY}")
message(STATUS "LLVM: ${LLVM_LIBRARY}")

add_executable(fuzzfw-analyze clang/main.cpp)
target_include_directories(fuzzfw-analyze PRIVATE ${LLVM_INCLUDE_DIR} ${CLANG_INCLUDE_DIR})
if(FUZZFW_CLANG_COMPONENTS)
  target_link_libraries(fuzzfw-analyze PRIVATE
    clangTooling clangFrontend clangSerialization clangAST clangBasic
    clangDriver clangParse clangSema clangAnalysis clangEdit clangLex
    clangSupport LLVM)
else()
  target_link_libraries(fuzzfw-analyze PRIVATE ${CLANG_CPP_LIBRARY} ${LLVM_LIBRARY})
endif()
if(UNIX AND EXISTS "/usr/lib64/llvm22/lib64")
  target_link_options(fuzzfw-analyze PRIVATE -Wl,-rpath,/usr/lib64/llvm22/lib64)
endif()

# The IR analyzer is built when its source is present. The Go fallback remains
# available for environments without LLVM development headers.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/llvm/main.cpp")
  add_executable(fuzzfw-ir-analyze llvm/main.cpp)
  target_include_directories(fuzzfw-ir-analyze PRIVATE ${LLVM_INCLUDE_DIR})
  if(FUZZFW_CLANG_COMPONENTS)
    target_link_libraries(fuzzfw-ir-analyze PRIVATE LLVM)
  else()
    target_link_libraries(fuzzfw-ir-analyze PRIVATE ${LLVM_LIBRARY})
  endif()
endif()

install(TARGETS fuzzfw-analyze RUNTIME DESTINATION bin)
if(TARGET fuzzfw-ir-analyze)
  install(TARGETS fuzzfw-ir-analyze RUNTIME DESTINATION bin)
endif()
