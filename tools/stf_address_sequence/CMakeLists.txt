project(stf_address_sequence)

add_executable(stf_address_sequence stf_address_sequence.cpp)

target_compile_options(stf_address_sequence PRIVATE -Wno-unused-result)

target_link_libraries(stf_address_sequence ${STF_LINK_LIBS})
