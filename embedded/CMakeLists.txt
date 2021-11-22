cmake_minimum_required(VERSION 3.1)
project(embedded VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_USE_STATIC_LIBS ON)

find_package(Threads REQUIRED)
find_package(Boost 1.47.0 REQUIRED COMPONENTS filesystem program_options thread)

if(WIN32)
    find_package(Libevent CONFIG REQUIRED)

    set(Bitcoin_LIBRARIES 
        bitcoin_common
        bitcoin_util
        bitcoin_server
        bitcoin_wallet
        bitcoinconsensus
        bitcoin_crypto
        secp256k1
        leveldb
        univalue
    )
    foreach(btclib ${Bitcoin_LIBRARIES})
        add_library(${btclib} STATIC IMPORTED)
        set_target_properties(${btclib} PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../contrib/bitcoin/build_msvc/x64/Release/lib${btclib}/lib${btclib}.lib")
    endforeach()
else()
    find_library(event_lib NAMES libevent.a event)
    if (NOT event_lib)
        message(FATAL_ERROR "libevent not found")
    endif()
    add_library(event STATIC IMPORTED)
    set_target_properties(event PROPERTIES IMPORTED_LOCATION ${event_lib})

    find_library(event_pthreads_lib NAMES libevent_pthreads.a event_pthreads)
    if (NOT event_pthreads_lib)
        message(FATAL_ERROR "libevent_pthreads not found")
    endif()
    add_library(event_pthreads STATIC IMPORTED)
    set_target_properties(event_pthreads PROPERTIES IMPORTED_LOCATION ${event_pthreads_lib})

    set(Bitcoin_LIBRARIES 
        bitcoin_common
        bitcoin_util
        bitcoin_server
        bitcoin_wallet
        bitcoin_consensus
        bitcoin_crypto_base
        bitcoin_crypto_shani
        bitcoin_crypto_sse41
        bitcoin_crypto_avx2
        secp256k1
        leveldb
        univalue
        memenv
        crc32c
        crc32c_sse42
    )
    set(Bitcoin_PATHS "${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src")
    set(Bitcoin_PATH_SUFFIXES "univalue/.libs" "leveldb" "crc32c" "crypto" "secp256k1/.libs")
    foreach(btclib ${Bitcoin_LIBRARIES})
        find_library(${btclib}_location ${btclib} PATHS ${Bitcoin_PATHS} PATH_SUFFIXES ${Bitcoin_PATH_SUFFIXES} NO_DEFAULT_PATH)
        if (NOT ${btclib}_location)
            message(FATAL_ERROR "${btclib} not found")
        endif()
        add_library(${btclib} STATIC IMPORTED)
        set_target_properties(${btclib} PROPERTIES IMPORTED_LOCATION ${${btclib}_location})
    endforeach()
endif()

set(Bitcoin_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src/univalue/include
    ${PROJECT_SOURCE_DIR}/../contrib/bitcoin/src/leveldb/include
)

add_library("${PROJECT_NAME}" embeddedrpc.cpp)

set(PROJECT_LIBRARIES
    ${Bitcoin_LIBRARIES}
    ${Boost_LIBRARIES}
)

if(WIN32)
    target_compile_options("${PROJECT_NAME}" PUBLIC /MT)
    target_link_options("${PROJECT_NAME}" PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
    set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} libevent::core libevent::extra)
else()
    set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} event event_pthreads)
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC ${PROJECT_LIBRARIES})
target_include_directories("${PROJECT_NAME}" PUBLIC 
    "${PROJECT_SOURCE_DIR}"
    ${Bitcoin_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
)