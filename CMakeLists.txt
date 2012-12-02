cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
cmake_policy (VERSION 2.6.0)

set(CMAKE_SKIP_RPATH FALSE)
set(CMAKE_SKIP_BUILD_RPATH  FALSE)

project (eblob)
FILE (READ "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+)" DEBFULLVERSION "${DEBCHANGELOG}")
STRING (REGEX MATCH "([0-9]+\\.[0-9]+)" EBLOB_VERSION_ABI "${DEBFULLVERSION}")
STRING (REGEX MATCH "([0-9]+$)" EBLOB_VERSION_MINOR "${DEBFULLVERSION}")

set(EBLOB_VERSION "${EBLOB_VERSION_ABI}.${EBLOB_VERSION_MINOR}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

option(WITH_ASSERTS "Enable asserts" OFF)
option(WITH_PYTHON "Build python bindings" ON)
option(WITH_EXAMPLES "Build examples" ON)
option(WITH_TESTS "Build tests" ON)
option(WITH_SNAPPY "Enable Snappy support" ON)

include(CheckAtomic)
include(TestBigEndian)

include_directories(${CMAKE_BINARY_DIR}/include/)

# Turn off aserts
if(!WITH_ASSERTS)
    add_definitions(-DNDEBUG)
endif()
message(STATUS "Asserts are: ${WITH_ASSERTS}")

# Test endianess
test_big_endian(HAVE_BIG_ENDIAN)
if(HAVE_BIG_ENDIAN)
    add_definitions(-DBYTEORDER=4321)
    add_definitions(-DWORDS_BIGENDIAN=1)
else()
    add_definitions(-DBYTEORDER=1234)
endif()

if (UNIX OR MINGW)
    #
    # Strict Aliasing notes:
    #   Currently there are couple of memory aliases represented by char** and
    #     void** casts in blob.c and mobjects.c
    #   GCC prints warnings if compiling with -fstrict-aliasing
    #   One can increase verbosity by setting -Wstrict-aliasing=2
    #
    # Useful warning options not implied by -Wall and -Wextra:
    #   -Wredundant-decls
    #   -Wmissing-declarations
    #   -Wstrict-overflow=4
    #
    add_definitions(-Wall -Wextra -fstack-protector-all -fno-strict-aliasing)
endif()
if (${CMAKE_SYSTEM_NAME} MATCHES BSD)
    add_definitions(-D__BSD_VISIBLE=1)
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
find_package(Boost REQUIRED COMPONENTS iostreams thread system regex python)
message(STATUS "Boost information:")
message(STATUS "  Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "  Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
message(STATUS "  Boost_LIBRARIES: ${Boost_LIBRARIES}")
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

# Check for snappy - unusual dependency, it doesn't use pkgconfig
if (WITH_SNAPPY)
    find_package(SNAPPY REQUIRED)
    include_directories(${SNAPPY_INCLUDE_DIR})
    add_definitions(-DHAVE_SNAPPY_SUPPORT)
endif()

# Check for python
if(WITH_PYTHON)
    find_package(PythonLibs REQUIRED)
    message(STATUS "Python includes are situated in (${PYTHON_INCLUDE_PATH}, ${PYTHON_INCLUDE_DIRS})")
    include_directories(${PYTHON_INCLUDE_PATH})
    include_directories(${PYTHON_INCLUDE_DIRS})
endif()

# Check for posix_fadvise
include(CheckSymbolExists)
check_symbol_exists(posix_fadvise "fcntl.h" HAVE_POSIX_FADVISE)
if (HAVE_POSIX_FADVISE)
    add_definitions(-DHAVE_POSIX_FADVISE)
endif()

# Collect all libraries together
set(EBLOB_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} ${SNAPPY_LIBRARIES})
set(EBLOB_CPP_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} ${Boost_IOSTREAMS_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY})
set(EBLOB_PYTHON_LIBRARIES ${Boost_PYTHON_LIBRARY} ${PYTHON_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

# Build parts
add_subdirectory(library)
if (WITH_EXAMPLES)
    add_subdirectory(example)
endif()
if (WITH_TESTS)
    add_subdirectory(tests)
endif()
add_subdirectory(bindings)

install(FILES
    include/eblob/eblob.hpp
    include/eblob/blob.h
    DESTINATION include/eblob/
    )
