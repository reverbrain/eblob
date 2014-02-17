set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

add_library(react STATIC react.h react.cpp)

if(UNIX OR MINGW)
	set_target_properties(react PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
