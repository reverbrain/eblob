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
include(cmake/Modules/locate_library.cmake)

locate_library(HANDYSTATS "handystats/core.hpp" "handystats")
include_directories(${HANDYSTATS_INCLUDE_DIRS})
link_directories(${HANDYSTATS_LIBRARY_DIRS})

include(CheckAtomic)
include(CheckSymbolExists)

option(WITH_ASSERTS "Enable asserts" OFF)
option(WITH_HARDENING "Enable hardening" OFF)
option(WITH_ASAN "Enable address sanitizer" OFF)
option(WITH_MSAN "Enable memory sanitizer" OFF)
option(WITH_TSAN "Enable thread sanitizer" OFF)
option(WITH_PYTHON "Build python bindings" ON)
option(WITH_EXAMPLES "Build examples" ON)
option(WITH_TESTS "Build tests" ON)
option(WITH_STATS "Build with runtime statistics gathering" ON)

# Turn off aserts
if (NOT WITH_ASSERTS)
    add_definitions(-DNDEBUG)
endif (NOT WITH_ASSERTS)
message(STATUS "Asserts are: ${WITH_ASSERTS}")

# Enable hardening
if (WITH_HARDENING)
    add_definitions(
        -D_FORTIFY_SOURCE=2
        -fpic
    )
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
        add_definitions(
            -pie
            -z now
            -z relro
        )
    endif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
endif (WITH_HARDENING)
message(STATUS "Hardening is: ${WITH_HARDENING}")

if (WITH_ASAN)
    add_definitions(
        -fno-omit-frame-pointer
        -fsanitize=address
    )
    set(SANITIZER_LIBRARY "-lasan")
endif (WITH_ASAN)
message(STATUS "asan is: ${WITH_ASAN}")

if (WITH_MSAN)
    add_definitions(
        -fno-omit-frame-pointer
        -fpic
        -fsanitize-memory-track-origins
        -fsanitize=memory
    )
    set(SANITIZER_LIBRARY "-lmsan")
endif (WITH_MSAN)
message(STATUS "msan is: ${WITH_MSAN}")

if (WITH_TSAN)
    add_definitions(
        -fno-omit-frame-pointer
        -fpic
        -fsanitize=thread
    )
    set(SANITIZER_LIBRARY "-ltsan")
endif (WITH_TSAN)
message(STATUS "tsan is: ${WITH_TSAN}")

message(STATUS "Sanitizer lib: ${SANITIZER_LIBRARY}")

# Test endianess
include(TestBigEndian)
test_big_endian(HAVE_BIG_ENDIAN)
if(HAVE_BIG_ENDIAN)
    add_definitions(-DBYTEORDER=4321)
    add_definitions(-DWORDS_BIGENDIAN=1)
else()
    add_definitions(-DBYTEORDER=1234)
endif()

# We use gnu extensions and C99 standard
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wredundant-decls")
add_definitions(
    -W
    -Wall
    -Wextra
    -Wstrict-aliasing=2
    -fstack-protector-all
    -fstrict-aliasing
)

# GCC's builtin memcmp is slower than libc's
# See: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=43052
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
add_definitions(
	-fno-builtin-memcmp
)
endif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")

if (${CMAKE_SYSTEM_NAME} MATCHES BSD)
    add_definitions(-D__BSD_VISIBLE=1)
endif()

# PThreads
set(CMAKE_THREAD_PREFER_PTHREAD ON)
find_package(Threads REQUIRED)

# Check for boost
find_package(Boost REQUIRED COMPONENTS iostreams thread system regex python)
message(STATUS "Boost information:")
message(STATUS "  Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "  Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
message(STATUS "  Boost_LIBRARIES: ${Boost_LIBRARIES}")


include_directories(
	${CMAKE_SOURCE_DIR}/include/
	${Boost_INCLUDE_DIRS}
)

link_directories(
	${Boost_LIBRARY_DIRS}
)


# Check for python
if(WITH_PYTHON)
    find_package(PythonLibs REQUIRED)
    message(STATUS "Python includes are situated in (${PYTHON_INCLUDE_PATH}, ${PYTHON_INCLUDE_DIRS})")
    include_directories(${PYTHON_INCLUDE_PATH})
    include_directories(${PYTHON_INCLUDE_DIRS})
endif()

# Check for posix_fadvise
check_symbol_exists(posix_fadvise "fcntl.h" HAVE_POSIX_FADVISE)
if (HAVE_POSIX_FADVISE)
    add_definitions(-DHAVE_POSIX_FADVISE)
endif()

# Check for posix_fallocate
check_symbol_exists(posix_fallocate "fcntl.h" HAVE_POSIX_FALLOCATE)
if (HAVE_POSIX_FALLOCATE)
    add_definitions(-DHAVE_POSIX_FALLOCATE)
endif()

# Check for fdatasync
check_symbol_exists(fdatasync "unistd.h" HAVE_FDATASYNC)
if (HAVE_FDATASYNC)
    add_definitions(-DHAVE_FDATASYNC)
endif()

# Check for handystats
if (WITH_STATS)
    find_package(Handystats REQUIRED)
    include_directories(${HANDYSTATS_INCLUDE_DIRS})
    add_definitions(${HANDYSTATS_CFLAGS})
else()
    # Handystats symbols are spilled across many source files,
    # so even if we do want to disable handystats instrumentation,
    # handystats headers still needed to define macros as empty stubs.
    find_package(Handystats)
    if (HANDYSTATS_FOUND)
        add_definitions(${HANDYSTATS_CFLAGS})
        add_definitions("-DHANDYSTATS_DISABLE=1")
    endif()
endif()

# Collect all libraries together
set(EBLOB_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} ${SANITIZER_LIBRARY})
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
