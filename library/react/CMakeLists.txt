add_library(eblob_react STATIC
	eblob_react.h
	eblob_react_actions.h
	eblob_react_actions.cpp
)

if(UNIX OR MINGW)
	set_target_properties(eblob_react PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

target_link_libraries(eblob_react react)
