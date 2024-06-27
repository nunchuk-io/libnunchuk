cmake_minimum_required(VERSION 3.1)
project(embedded VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_USE_STATIC_LIBS ON)
set(BITCOIN_FOLDER "contrib/bitcoin")
if(ANDROID)
    if (${ANDROID_ABI} STREQUAL "armeabi-v7a")
        set(BITCOIN_FOLDER "contrib/bitcoin-arm8")
    endif ()
elseif(NOT ANDROID)
    find_package(Threads REQUIRED)
    find_package(Boost 1.47.0 REQUIRED COMPONENTS filesystem)
endif()

set(UR__DISABLE_TESTS ON)

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
        set_target_properties(${btclib} PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/build_msvc/x64/Release/lib${btclib}/lib${btclib}.lib")
    endforeach()
elseif(ANDROID)
    add_library(event STATIC IMPORTED)
    set_target_properties(event PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/depends/${ANDROID_TARGET}/lib/libevent.a")
    add_library(event_pthreads STATIC IMPORTED)
    set_target_properties(event_pthreads PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/depends/${ANDROID_TARGET}/lib/libevent_pthreads.a")

    if(ANDROID_ABI_ARM_64)
        set(Bitcoin_LIBRARIES
            bitcoin_common
            bitcoin_util
            bitcoin_server
            bitcoin_wallet
            bitcoin_consensus
            bitcoin_crypto_base
            secp256k1
            leveldb
            univalue
            memenv
            crc32c
            crc32c_arm_crc
        )
    elseif(ANDROID_ABI_ARM)
        set(Bitcoin_LIBRARIES
            bitcoin_common
            bitcoin_util
            bitcoin_server
            bitcoin_wallet
            bitcoin_consensus
            bitcoin_crypto_base
            secp256k1
            leveldb
            univalue
            memenv
            crc32c
        )
    else()
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
    endif()

    set(Bitcoin_PATHS "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src")
    foreach(btclib common util server wallet consensus)
        add_library(bitcoin_${btclib} STATIC IMPORTED)
        set_target_properties(bitcoin_${btclib} PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/libbitcoin_${btclib}.a)
    endforeach()
    if(ANDROID_ABI_ARM)
        add_library(bitcoin_crypto_base STATIC IMPORTED)
        set_target_properties(bitcoin_crypto_base PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/crypto/libbitcoin_crypto_base.a)
    else()
        foreach(cryptolib base shani sse41 avx2)
            add_library(bitcoin_crypto_${cryptolib} STATIC IMPORTED)
            set_target_properties(bitcoin_crypto_${cryptolib} PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/crypto/libbitcoin_crypto_${cryptolib}.a)
        endforeach()
    endif()

    add_library(secp256k1 STATIC IMPORTED)
    set_target_properties(secp256k1 PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/secp256k1/.libs/libsecp256k1.a)
    add_library(leveldb STATIC IMPORTED)
    set_target_properties(leveldb PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/leveldb/libleveldb.a)
    add_library(memenv STATIC IMPORTED)
    set_target_properties(memenv PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/leveldb/libmemenv.a)
    add_library(univalue STATIC IMPORTED)
    set_target_properties(univalue PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/univalue/.libs/libunivalue.a)
    add_library(crc32c STATIC IMPORTED)
    set_target_properties(crc32c PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/crc32c/libcrc32c.a)
    if(NOT ANDROID_ABI_ARM)
        add_library(crc32c_sse42 STATIC IMPORTED)
        set_target_properties(crc32c_sse42 PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/crc32c/libcrc32c_sse42.a)
    elseif(ANDROID_ABI_ARM_64)
        add_library(crc32c_arm_crc STATIC IMPORTED)
        set_target_properties(crc32c_arm_crc PROPERTIES IMPORTED_LOCATION ${Bitcoin_PATHS}/crc32c/libcrc32c_arm_crc.a)
    endif()

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
        bitcoinconsensus
        bitcoin_crypto_x86_shani
        bitcoin_crypto_sse41
        bitcoin_crypto_avx2
        secp256k1
        leveldb
        univalue
        memenv
        crc32c
        crc32c_sse42
    )
    set(Bitcoin_PATHS "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src")
    set(Bitcoin_PATH_SUFFIXES ".libs" "leveldb/.libs" "crc32c/.libs" "crypto/.libs" "secp256k1/.libs")
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
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/univalue/include
    ${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/leveldb/include
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
    "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/secp256k1/include"
    "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/depends/${ANDROID_TARGET}/include"
)

# Pass secp256k1 for tap-protocol
get_target_property(SECP256K1_LIBRARY secp256k1 IMPORTED_LOCATION)
set(EXTERNAL_SECP256K1_LIBRARY "${SECP256K1_LIBRARY}" PARENT_SCOPE)
set(EXTERNAL_SECP256K1_INCLUDE "${PROJECT_SOURCE_DIR}/../${BITCOIN_FOLDER}/src/secp256k1/include" PARENT_SCOPE)
# set(USE_EXTERNAL_SECP256K1 ON PARENT_SCOPE)
