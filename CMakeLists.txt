cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
cmake_policy (VERSION 2.6.0)

project (eblob)
set(EBLOB_VERSION_ABI "0")
set(EBLOB_VERSION_MINOR "16.6")

set(EBLOB_VERSION "${EBLOB_VERSION_ABI}.${EBLOB_VERSION_MINOR}")

if (UNIX OR MINGW)
    add_definitions(-W -Wall -Wextra -fstack-protector-all -fno-strict-aliasing)
endif()

# Check for threads
if (UNIX AND BSD)
    set(CMAKE_THREAD_LIBS -pthread)
    set(CMAKE_USE_PTHREADS ON)
    set(CMAKE_EXE_LINKER_FLAGS -pthread)
endif()

set(CMAKE_THREAD_PREFER_PTHREAD ON)
find_package(Threads REQUIRED)

# Check for boost
#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_STLPORT ON)
find_package(Boost REQUIRED COMPONENTS iostreams thread regex python)
include_directories(${Boost_INCLUDE_DIRS})

# Check for snappy - unusual dependency, it doesn't use pkgconfig
if(SNAPPY)
    include_directories("${SNAPPY}/include")
endif()
find_library(SNAPPY_LIBRARIES snappy HINTS ${SNAPPY})
if(NOT SNAPPY_LIBRARIES)
    message(FATAL "Cannot find Snappy. You may want to install Snappy from http://code.google.com/p/snappy/ to get compression support")
endif()
add_definitions(-DHAVE_SNAPPY_SUPPORT)

# Collect all libraries together
SET(EBLOB_LIBRARIES ${Boost_LIBRARIES} ${SNAPPY_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

# Build parts
add_subdirectory(library)
add_subdirectory(example)
add_subdirectory(bindings)

install(FILES include/eblob/eblob.hpp include/eblob/blob.h
    DESTINATION include/eblob/
    )
