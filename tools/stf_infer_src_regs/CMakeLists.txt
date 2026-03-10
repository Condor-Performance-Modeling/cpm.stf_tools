project(stf_infer_src_regs)

include(${STF_TOOLS_CMAKE_DIR}/disassembler.cmake)

add_executable(stf_infer_src_regs stf_infer_src_regs.cpp)

target_link_libraries(stf_infer_src_regs ${STF_LINK_LIBS})
