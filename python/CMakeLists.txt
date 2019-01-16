cmake_minimum_required(VERSION 3.10)

project(SEAL-python)

find_package(SEAL 3.1.0)

add_subdirectory(pybind11)
pybind11_add_module(_seal wrapper.cpp)
target_compile_features(_seal PUBLIC cxx_std_17)
target_link_libraries(_seal PRIVATE seal)
