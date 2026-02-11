cmake_minimum_required(VERSION 3.22)
project(tink_ffi LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED TINK_CC_DIR)
    message(FATAL_ERROR "TINK_CC_DIR must be set to the tink-cc source tree")
endif()

# tink-cc requires static libraries.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(TINK_BUILD_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory("${TINK_CC_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/tink-cc")

file(GLOB TINK_FFI_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")

add_library(tink_ffi STATIC ${TINK_FFI_SRCS})

target_include_directories(tink_ffi PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(tink_ffi PUBLIC
    tink::static
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac_config
    tink::jwt::jwt_signature_config
    tink::jwt::jwt_mac_config_v0
    tink::jwt::jwt_signature_config_v0
    tink::prf::prf_key_templates
    tink::prf::config_v0
    tink::keyderivation::key_derivation_config
    tink::keyderivation::key_derivation_key_templates
    tink::keyderivation::keyset_deriver
    tink::config::global_registry
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::hybrid::hpke_config
    tink::hybrid::config_v0
    tink::streamingaead::config_v0
    tink::mac::config_v0
    tink::signature::config_v0
)
