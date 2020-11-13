cmake_minimum_required(VERSION 3.1)
project(test-nunchuk)

enable_testing()
add_library(unittest_main OBJECT src/unit.cpp)

set(files
    src/coreutils_test.cpp
    src/descriptor_test.cpp
    src/nunchukutils_test.cpp
    src/utils/addressutils_test.cpp
    src/utils/bip32_test.cpp
    src/utils/txutils_test.cpp)

foreach(file ${files})
    get_filename_component(testcase ${file} NAME_WE)
    add_executable(${testcase} ${file} $<TARGET_OBJECTS:unittest_main>)
    target_link_libraries(${testcase} nunchuk)
    target_include_directories(${testcase} PUBLIC "${PROJECT_SOURCE_DIR}/src")
    add_test(NAME ${testcase} COMMAND ${testcase})
endforeach()