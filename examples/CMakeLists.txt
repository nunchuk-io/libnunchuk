cmake_minimum_required(VERSION 3.1)
project(nunchuk-examples VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(.. lib EXCLUDE_FROM_ALL)

add_executable("${PROJECT_NAME}" main.cpp)
target_link_libraries("${PROJECT_NAME}" PUBLIC nunchuk)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
