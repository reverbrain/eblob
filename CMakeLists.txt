cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
cmake_policy (VERSION 2.6.0)
set(CMAKE_SKIP_RPATH TRUE)

project (eblob)
set(EBLOB_VERSION_ABI "0")
set(EBLOB_VERSION_MINOR "16.6")

set(EBLOB_VERSION "${EBLOB_VERSION_ABI}.${EBLOB_VERSION_MINOR}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

include(CheckAtomic)
include(TestBigEndian)

# Test endianess
test_big_endian(HAVE_BIG_ENDIAN)
if(HAVE_BIG_ENDIAN)
    add_definitions(-DBYTEORDER=4321)
    add_definitions(-DWORDS_BIGENDIAN=1)
else()
    add_definitions(-DBYTEORDER=1234)
endif()

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
include(CheckThreadSpinlock)

# Check for boost
#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_STLPORT ON)
find_package(Boost REQUIRED COMPONENTS iostreams thread regex python)
include_directories(${Boost_INCLUDE_DIRS})
message(STATUS "Boost includes are situated in ${Boost_INCLUDE_DIRS}")

# Check for snappy - unusual dependency, it doesn't use pkgconfig
find_package(SNAPPY REQUIRED)
include_directories(${SNAPPY_INCLUDE_DIR})
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
