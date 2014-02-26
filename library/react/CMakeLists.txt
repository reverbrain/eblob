set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

add_library(eblob_actions STATIC eblob_actions.h eblob_actions.cpp)

if(UNIX OR MINGW)
	set_target_properties(eblob_actions PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
