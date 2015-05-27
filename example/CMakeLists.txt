add_executable(eblob_merge merge.cpp)
target_link_libraries(eblob_merge eblob_cpp)

add_executable(eblob_index_info eblob_index_info.cpp)
target_link_libraries(eblob_index_info eblob_cpp)

add_executable(eblob_to_index blob_to_index.cpp)
target_link_libraries(eblob_to_index eblob_cpp)

install(TARGETS eblob_merge eblob_index_info eblob_to_index
    RUNTIME DESTINATION bin
    )
