add_subdirectory(python)

include_directories(../../include)
add_library(eblob_python SHARED eblob_python.cpp)
target_link_libraries(eblob_python eblob eblob_cpp ${EBLOB_PYTHON_LIBRARIES})

install(TARGETS eblob_python
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )

# vim: set ts=4:sw=4:expandtab:
