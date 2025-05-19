cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)
project(sqlcipher VERSION 0.1.0)

set(SQLITE_SOURCE
  sqlcipher/sqlite3.c
  sqlcipher/sqlite3.h
  sqlcipher/sqlite3ext.h
  sqlcipher/sqlite3session.h
)

find_package(OpenSSL REQUIRED)

add_library("${PROJECT_NAME}" STATIC ${SQLITE_SOURCE})
target_include_directories("${PROJECT_NAME}" PUBLIC
        "${PROJECT_SOURCE_DIR}"
        "${PROJECT_SOURCE_DIR}/sqlcipher"
        )
target_link_libraries("${PROJECT_NAME}" PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if (WIN32)
  if (MINGW)
    target_link_libraries("${PROJECT_NAME}" PRIVATE ws2_32 mswsock crypt32)
  else()
    target_link_libraries("${PROJECT_NAME}" PRIVATE ws2_32 Mswsock Crypt32)
  endif()
else()
  target_link_libraries("${PROJECT_NAME}" PRIVATE dl)
endif()

target_compile_definitions("${PROJECT_NAME}" PRIVATE
  -DSQLITE_DEFAULT_MEMSTATUS=0
  -DSQLITE_OMIT_LOAD_EXTENSION
  -DSQLITE_OMIT_DECLTYPE
  -DSQLITE_OMIT_PROGRESS_CALLBACK
  -DSQLITE_OMIT_DEPRECATED
  #-DSQLITE_OMIT_SHARED_CACHE
)
target_compile_definitions("${PROJECT_NAME}" PRIVATE -DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2 -DSQLITE_ENABLE_FTS5 -DSQLITE_DISABLE_LFS)

if (NOT WIN32)
  target_compile_definitions("${PROJECT_NAME}" PRIVATE -DHAVE_USLEEP -DNDEBUG=1)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
  target_compile_definitions("${PROJECT_NAME}" PRIVATE -DSQLITE_OS_WINRT=1)
endif()

if (GCC OR CLANG)
  target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-const-variable -Wno-unused-function)
  if (CLANG)
    target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-parentheses-equality -Wno-unused-value -Wno-unused-command-line-argument -Qunused-arguments)
  endif()
  if (GCC AND NOT (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0))
    target_compile_options("${PROJECT_NAME}" PRIVATE -Wno-return-local-addr -Wno-stringop-overflow)
  endif()
elseif (MSVC)
  target_compile_options("${PROJECT_NAME}" PRIVATE /wd4996)
endif()
