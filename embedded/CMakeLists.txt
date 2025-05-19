cmake_minimum_required(VERSION 3.1)
project(embedded VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_USE_STATIC_LIBS ON)
   
find_package(Threads REQUIRED)
find_package(Boost 1.47.0 REQUIRED)

set(Bitcoin_LIBRARIES 
	bitcoin_common
	bitcoin_util
	bitcoin_cli
	bitcoin_node
	bitcoin_wallet
	bitcoin_crypto
	secp256k1
	univalue
)

set(Bitcoin_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/build/src
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src/univalue/include
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src/leveldb/include
)

add_library("${PROJECT_NAME}" STATIC embeddedrpc.cpp)

set(PROJECT_LIBRARIES
    ${Bitcoin_LIBRARIES}
    ${Boost_LIBRARIES}
)

target_link_libraries("${PROJECT_NAME}" PRIVATE ${PROJECT_LIBRARIES})

target_include_directories("${PROJECT_NAME}" PUBLIC 
    "${PROJECT_SOURCE_DIR}"
    ${Bitcoin_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    "${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src/secp256k1/include"
    "${PROJECT_BINARY_DIR}/../contrib/bitcoin/src"
    "${PROJECT_SOURCE_DIR}/../contrib/bitcoin/depends/${ANDROID_TARGET}/include"
)
