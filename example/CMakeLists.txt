include_directories(../include)

add_executable(eblob_open eblob_open.cpp)
target_link_libraries(eblob_open eblob_cpp)

add_executable(eblob_merge merge.cpp)
target_link_libraries(eblob_merge eblob_cpp)

#add_executable(eblob_iterate_send iterate_send.cpp)
#set(EBLOB_ITERATE_SEND_LIBRARIES eblob_cpp ${Boost_LIBRARIES})
#target_link_libraries(eblob_iterate_send ${EBLOB_ITERATE_SEND_LIBRARIES})

add_executable(eblob_index_info eblob_index_info.cpp)
target_link_libraries(eblob_index_info eblob_cpp)

set(EBLOB_REGEX_ITER_SRCS eblob_regex_iter.cpp)
add_executable(eblob_regex_iter ${EBLOB_REGEX_ITER_SRCS})
set(EBLOB_REGEX_ITER_LIBRARIES eblob_cpp ${Boost_SYSTEM_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_IOSTREAMS_LIBRARY})
target_link_libraries(eblob_regex_iter ${EBLOB_REGEX_ITER_LIBRARIES})

install(TARGETS eblob_regex_iter eblob_merge eblob_open eblob_index_info # eblob_iterate_send
    RUNTIME DESTINATION bin
    )

