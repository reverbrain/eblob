include_directories(../include)

# stress
add_executable(eblob_stress stress/stress.c stress/options.c)
target_link_libraries(eblob_stress eblob)

# cpp bindings
set(EBLOB_CPP_TEST_SRCS cpp/test.cpp)
add_executable(eblob_cpp_test ${EBLOB_CPP_TEST_SRCS})
target_link_libraries(eblob_cpp_test ${EBLOB_CPP_LIBRARIES} eblob_cpp eblob)

# unit tests
set(TEST_NAME eblob_crypto_test)
set(EBLOB_UNIT_CRYPTO_SRCS unit/crypto.cpp)
add_executable(${TEST_NAME} ${EBLOB_UNIT_CRYPTO_SRCS})
target_link_libraries(${TEST_NAME} eblob -lboost_unit_test_framework)

set(TESTS_LIST eblob_stress eblob_cpp_test eblob_crypto_test)
set(TESTS_DEPS ${TESTS_LIST})

add_custom_target(test
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh"
  DEPENDS ${TESTS_DEPS})
