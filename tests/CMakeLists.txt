include_directories(../include)
add_executable(eblob_stress stress/stress.c stress/options.c)
target_link_libraries(eblob_stress eblob)

enable_testing()
add_test(data_sort eblob_stress)
