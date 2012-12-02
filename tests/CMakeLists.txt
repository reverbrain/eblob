include_directories(../include)
add_executable(test_datasort datasort/test_datasort.c datasort/options.c)
target_link_libraries(test_datasort eblob)

enable_testing()
add_test(data_sort test_datasort)
