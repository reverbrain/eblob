include_directories(../../include)
set(EBLOB_CPP_SRCS
    eblob.cpp
    iterator.cpp
    )
set(EBLOB_CPP_TEST_SRCS
    test.cpp
    )

add_library(eblob_cpp SHARED ${EBLOB_CPP_SRCS})
set_target_properties(eblob_cpp PROPERTIES
    VERSION ${EBLOB_VERSION}
    SOVERSION ${EBLOB_VERSION_ABI}
    )
target_link_libraries(eblob_cpp ${EBLOB_LIBRARIES} eblob)

add_library(eblob_cpp_static STATIC ${EBLOB_CPP_SRCS})
set_target_properties(eblob_cpp_static PROPERTIES
    OUTPUT_NAME eblob_cpp
    )
target_link_libraries(eblob_cpp_static ${EBLOB_LIBRARIES} eblob_static)

add_executable(eblob_cpp_test ${EBLOB_CPP_TEST_SRCS})
target_link_libraries(eblob_cpp_test ${EBLOB_LIBRARIES} eblob_cpp eblob)

install(TARGETS eblob_cpp eblob_cpp_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
