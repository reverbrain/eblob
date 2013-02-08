include_directories(../include)

# stress
add_executable(eblob_stress stress/stress.c stress/options.c)
target_link_libraries(eblob_stress eblob)

# cpp bindings
set(EBLOB_CPP_TEST_SRCS cpp/test.cpp)
add_executable(eblob_cpp_test ${EBLOB_CPP_TEST_SRCS})
target_link_libraries(eblob_cpp_test ${EBLOB_CPP_LIBRARIES} eblob_cpp eblob)
