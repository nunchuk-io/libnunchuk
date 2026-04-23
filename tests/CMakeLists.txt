cmake_minimum_required(VERSION 3.1)

# This directory can be built either standalone or as part of the top-level
# libnunchuk build. Avoid calling `project()` when included as a subdirectory.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(test-nunchuk)
endif()

enable_testing()
add_library(unittest_main OBJECT src/unit.cpp)

set(files
    src/coreutils_test.cpp
    src/descriptor_test.cpp
    src/nunchukutils_test.cpp
    src/utils/addressutils_test.cpp
    src/utils/attachment_test.cpp
    src/utils/bip32_test.cpp
    src/utils/silentpayment_test.cpp
    src/utils/txutils_test.cpp)

foreach(file ${files})
    get_filename_component(testcase ${file} NAME_WE)
    add_executable(${testcase} ${file} $<TARGET_OBJECTS:unittest_main>)
    target_link_libraries(${testcase} nunchuk)
    target_include_directories(${testcase} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../contrib/tap-protocol/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../contrib/tap-protocol/contrib/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src")
    add_test(NAME ${testcase} COMMAND ${testcase})
endforeach()