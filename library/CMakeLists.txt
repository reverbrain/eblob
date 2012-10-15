include_directories(../include)
set(EBLOB_SRCS
    blob.c
    hash.c
    log.c
    range.c
    mobjects.c
    compress.c
    defrag.c
    index.c
    crypto/sha512.c
    stat.c
    rbtree.c
    )
add_library(eblob SHARED ${EBLOB_SRCS})
set_target_properties(eblob PROPERTIES
    VERSION ${EBLOB_VERSION}
    SOVERSION ${EBLOB_VERSION_ABI}
    )

add_library(eblob_static STATIC ${EBLOB_SRCS})
set_target_properties(eblob_static PROPERTIES
    OUTPUT_NAME eblob
    )
target_link_libraries(eblob ${EBLOB_LIBRARIES} ${Boost_SYSTEM_LIBRARIES})
target_link_libraries(eblob_static ${EBLOB_LIBRARIES} ${Boost_SYSTEM_LIBRARIES})

install(TARGETS eblob eblob_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
