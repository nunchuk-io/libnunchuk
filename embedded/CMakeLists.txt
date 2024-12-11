cmake_minimum_required(VERSION 3.1)
project(embedded VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_USE_STATIC_LIBS ON)
set(BITCOIN_FOLDER "contrib/bitcoin")
   
find_package(Threads REQUIRED)
find_package(Boost 1.47.0 REQUIRED)

if(WIN32)
    find_package(Libevent CONFIG REQUIRED)

    set(Bitcoin_LIBRARIES 
        bitcoin_common
        bitcoin_util
        bitcoin_cli
        bitcoin_node
        bitcoin_wallet
        bitcoin_consensus
        bitcoin_crypto
        secp256k1
        univalue
    )
elseif(ANDROID OR IOS)
    set(Bitcoin_LIBRARIES
            bitcoin_common
            bitcoin_util
            bitcoin_node
            bitcoin_wallet
            secp256k1
            leveldb
            univalue
    )
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
        bitcoin_cli
        bitcoin_node
        bitcoin_wallet
        bitcoin_consensus
        bitcoin_crypto
        bitcoin_crypto_x86_shani
        bitcoin_crypto_sse41
        bitcoin_crypto_avx2
        secp256k1
        univalue
    )
endif()

set(Bitcoin_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/build/src
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/univalue/include
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/leveldb/include
)

add_library("${PROJECT_NAME}" STATIC embeddedrpc.cpp)

set(PROJECT_LIBRARIES
    ${Bitcoin_LIBRARIES}
    ${Boost_LIBRARIES}
)

if(WIN32)
    target_compile_options("${PROJECT_NAME}" PUBLIC /MT)
    target_link_options("${PROJECT_NAME}" PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
    set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} libevent::core libevent::extra)
elseif(ANDROID OR IOS)
    #set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} libevent::core libevent::extra)
else()
    set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} event event_pthreads)
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC ${PROJECT_LIBRARIES})

target_include_directories("${PROJECT_NAME}" PUBLIC 
    "${PROJECT_SOURCE_DIR}"
    ${Bitcoin_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/secp256k1/include"
    "${PROJECT_BINARY_DIR}/../${BITCOIN_FOLDER}/src"
    "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/depends/${ANDROID_TARGET}/include"
)
