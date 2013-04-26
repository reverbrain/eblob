add_subdirectory(cpp)
if(Boost_PYTHON_LIBRARY AND WITH_PYTHON)
    add_subdirectory(python)
endif()

# vim: set ts=4:sw=4:expandtab:
