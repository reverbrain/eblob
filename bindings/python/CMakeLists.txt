add_subdirectory(python)

find_package(PythonLibs REQUIRED)
message(STATUS "Python includes are situated in (${PYTHON_INCLUDE_PATH}, ${PYTHON_INCLUDE_DIRS})")

include_directories(../../include)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${PYTHON_INCLUDE_PATH})
add_library(eblob_python SHARED eblob_python.cpp)
set(EBLOB_PYTHON_LIBRARIES eblob eblob_cpp ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${PYTHON_LIBRARIES})
target_link_libraries(eblob_python eblob eblob_cpp ${EBLOB_PYTHON_LIBRARIES})

install(TARGETS eblob_python
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
