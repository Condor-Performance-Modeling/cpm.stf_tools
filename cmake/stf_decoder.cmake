include_guard(DIRECTORY)

include(${STF_TOOLS_CMAKE_DIR}/mavis.cmake)

set(STF_LINK_LIBS ${STF_LINK_LIBS} mavis mavis_json_files Boost::json)
