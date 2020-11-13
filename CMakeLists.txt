cmake_minimum_required(VERSION 3.1)
project(nunchuk VERSION 0.1.0)

configure_file(src/config.h.in nunchuk-config.h)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)
set(Boost_USE_STATIC_LIBS ON)

# Fetch HWI binary from github releases
include(FetchContent)
if(APPLE)
    set(HWI_URL "https://github.com/bitcoin-core/HWI/releases/download/1.2.0/hwi-1.2.0-mac-amd64.tar.gz")
    set(HWI_URL_HASH "SHA256=659c030f2c9a0be83823c17fe2ef2bac6ac90d95752f9c2eae51c8136ee77a10")
elseif(UNIX)
    set(HWI_URL "https://github.com/bitcoin-core/HWI/releases/download/1.2.0/hwi-1.2.0-linux-amd64.tar.gz")
    set(HWI_URL_HASH "SHA256=de02bc1acccbcf4d1592179835bc9ad0f8b9d81e1e615b0703db0608e9d2f063")
else()
    set(HWI_URL "https://github.com/bitcoin-core/HWI/releases/download/1.2.0/hwi-1.2.0-windows-amd64.zip")
    set(HWI_URL_HASH "SHA256=93386f83de3e09113b4fa2d5c326efa651c30281fa2c87034a6a9cab36634210")
endif()

FetchContent_Populate(
    hwi
    URL ${HWI_URL}
    URL_HASH ${HWI_URL_HASH}
    SOURCE_DIR bin
)

find_package(Threads REQUIRED)
find_package(Boost 1.47.0 REQUIRED COMPONENTS filesystem program_options thread)

if(WIN32)
    find_package(OpenSSL REQUIRED)
    add_library(sqlcipher STATIC IMPORTED)
    set_target_properties(sqlcipher PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/contrib/sqlcipher/libsqlcipher.lib")
else()
    find_library(sqlcipher_lib NAMES sqlcipher PATHS "${PROJECT_SOURCE_DIR}/contrib/sqlcipher/.libs" NO_DEFAULT_PATH)
    if (NOT sqlcipher_lib)
        message(FATAL_ERROR "sqlcipher not found")
    endif()
    add_library(sqlcipher STATIC IMPORTED)
    set_target_properties(sqlcipher PROPERTIES IMPORTED_LOCATION ${sqlcipher_lib})
endif()

add_subdirectory(embedded)

add_library("${PROJECT_NAME}"  
    src/hwiservice.cpp 
    src/coreutils.cpp
    src/descriptor.cpp
    src/electrumclient.cpp
    src/coinselector.cpp
    src/storage.cpp
    src/nunchukimpl.cpp
    src/nunchukutils.cpp
    src/synchronizer.cpp
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
    sqlcipher
    Threads::Threads
)
                            
if(WIN32)
    target_compile_options("${PROJECT_NAME}" PUBLIC /MT)
    target_link_options("${PROJECT_NAME}" PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)
    set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto crypt32 ws2_32)
elseif(UNIX AND NOT APPLE)
    set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} dl)
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC ${PROJECT_LIBRARIES})
target_include_directories("${PROJECT_NAME}" PUBLIC 
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/include"
    ${Boost_INCLUDE_DIRS}
    "${PROJECT_SOURCE_DIR}/contrib"
    "${PROJECT_BINARY_DIR}"
)

include(CTest)
add_subdirectory(tests)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
