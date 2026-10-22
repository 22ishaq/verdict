cmake_minimum_required(VERSION 3.20)
project(verdict_bindings LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# NR-Lite is vendored as a git submodule. Point NRLITE_SOURCE_DIR elsewhere to test a local checkout.
set(NRLITE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nr-lite" CACHE PATH "NR-Lite source tree")
if(NOT EXISTS "${NRLITE_SOURCE_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "NR-Lite not found at ${NRLITE_SOURCE_DIR}; run: git submodule update --init")
endif()
set(NRLITE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(NRLITE_BUILD_APPS OFF CACHE BOOL "" FORCE)
add_subdirectory(${NRLITE_SOURCE_DIR} nrlite EXCLUDE_FROM_ALL)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)
pybind11_add_module(_nrlite bindings/nrlite_py.cpp)
target_link_libraries(_nrlite PRIVATE nrlite::nrlite)

if(SKBUILD)
  install(TARGETS _nrlite DESTINATION verdict)
else()
  # Developer build: drop the module next to the Python package so `pytest` works in-tree.
  set_target_properties(_nrlite PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/verdict)
endif()
