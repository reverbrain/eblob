set(EBLOB_SRCS
    blob.c
    crypto/sha512.c
    datasort.c
    defrag.c
    hash.c
    index.c
    l2hash.c
    log.c
    mobjects.c
    range.c
    rbtree.c
    stat.c
    json_stat.cpp
    footer.cpp
    crc32.cpp
    )

add_definitions(-D__STDC_LIMIT_MACROS)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++0x")

add_library(eblob SHARED ${EBLOB_SRCS})

set_target_properties(eblob PROPERTIES
    VERSION ${EBLOB_VERSION}
    SOVERSION ${EBLOB_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )

target_link_libraries(eblob ${EBLOB_LIBRARIES} ${Boost_SYSTEM_LIBRARIES} handystats rt)

install(TARGETS eblob
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )

# vim: set ts=4:sw=4:expandtab:
