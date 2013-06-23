include_directories(../include)
set(EBLOB_SRCS
    binlog.c
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
    )
add_library(eblob SHARED ${EBLOB_SRCS})
set_target_properties(eblob PROPERTIES
    VERSION ${EBLOB_VERSION}
    SOVERSION ${EBLOB_VERSION_ABI}
    )

target_link_libraries(eblob ${EBLOB_LIBRARIES} ${Boost_SYSTEM_LIBRARIES})

install(TARGETS eblob
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )

# vim: set ts=4:sw=4:expandtab:
