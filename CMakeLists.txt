cmake_minimum_required(VERSION 3.28)

project(constexprSha-2)

set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH "Catch2/contrib")
include(CTest)
include(Catch)

add_subdirectory(tests)
