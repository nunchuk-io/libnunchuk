cmake_minimum_required(VERSION 3.1)
project(nunchuk VERSION 0.1.0)

configure_file(src/config.h.in nunchuk-config.h)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)
set(Boost_USE_STATIC_LIBS ON)
set(OPENSSL_USE_STATIC_LIBS ON)

find_package(Threads REQUIRED)
find_package(Boost 1.47.0 REQUIRED COMPONENTS filesystem program_options thread)
find_package(OpenSSL REQUIRED)

if(WIN32)
    find_package(sqlcipher CONFIG REQUIRED)
else()
    find_library(sqlcipher_lib NAMES libsqlcipher.a PATHS "${PROJECT_SOURCE_DIR}/contrib/sqlcipher/.libs" NO_DEFAULT_PATH)
    if (NOT sqlcipher_lib)
        message(FATAL_ERROR "sqlcipher not found")
    endif()
    add_library(sqlcipher STATIC IMPORTED)
    set_target_properties(sqlcipher PROPERTIES IMPORTED_LOCATION ${sqlcipher_lib})
endif()

add_subdirectory(embedded)

add_library("${PROJECT_NAME}" STATIC 
    src/hwiservice.cpp 
    src/coreutils.cpp
    src/descriptor.cpp
    src/coinselector.cpp
    src/storage.cpp
    src/nunchukimpl.cpp
    src/nunchukutils.cpp
    src/backend/synchronizer.cpp
    src/backend/electrum/client.cpp
    src/backend/electrum/synchronizer.cpp
    src/backend/corerpc/client.cpp
    src/backend/corerpc/synchronizer.cpp
    src/dto/appsettings.cpp
    src/dto/device.cpp
    src/dto/mastersigner.cpp
    src/dto/singlesigner.cpp
    src/dto/transaction.cpp
    src/dto/unspentoutput.cpp
    src/dto/wallet.cpp
    src/utils/loguru.cpp
)

set(PROJECT_LIBRARIES
    embedded
    OpenSSL::SSL OpenSSL::Crypto
    Threads::Threads
)
                            
if(WIN32)
    target_compile_options("${PROJECT_NAME}" PUBLIC /MT)
    target_link_options("${PROJECT_NAME}" PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
    set(PROJECT_LIBRARIES sqlcipher::sqlcipher ${PROJECT_LIBRARIES} crypt32 ws2_32)
elseif(APPLE)
    set(PROJECT_LIBRARIES sqlcipher ${PROJECT_LIBRARIES})
elseif(UNIX)
    set(PROJECT_LIBRARIES sqlcipher ${PROJECT_LIBRARIES} dl)
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC ${PROJECT_LIBRARIES})
target_include_directories("${PROJECT_NAME}" PUBLIC 
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/include"
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    "${PROJECT_SOURCE_DIR}/contrib"
    "${PROJECT_BINARY_DIR}"
)

include(CTest)
add_subdirectory(tests)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
