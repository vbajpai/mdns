# ---------------------------------------------------------------------------#
# ------------------------------- CMake -------------------------------------#
# ---------------------------------------------------------------------------#

# minimum supported cmake version
cmake_minimum_required(VERSION 2.6)

# identify the project and programming language
project(mdns C)

# compiler flags passed as arguments 
add_definitions(-Wall -Werror -std=c99)

# set output directories for libraries and executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# specify the TARGET executable
add_executable(querier ${CMAKE_SOURCE_DIR}/src/querier.c)
add_executable(viewer ${CMAKE_SOURCE_DIR}/src/viewer.c)

# ---------------------------------------------------------------------------#
