include_directories(../../include)
set(EBLOB_CPP_SRCS
    eblob.cpp
    iterator.cpp
    )

add_library(eblob_cpp SHARED ${EBLOB_CPP_SRCS})
set_target_properties(eblob_cpp PROPERTIES
    VERSION ${EBLOB_VERSION}
    SOVERSION ${EBLOB_VERSION_ABI}
    )
target_link_libraries(eblob_cpp ${EBLOB_CPP_LIBRARIES} eblob)

install(TARGETS eblob_cpp
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
