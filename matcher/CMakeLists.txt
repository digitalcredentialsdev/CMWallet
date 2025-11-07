cmake_minimum_required(VERSION 3.30)
project(Matcher)

# Add include directories
include_directories(. cJSON)

# Common library source files
set(COMMON_LIB_SRCS
    cJSON/cJSON.c
    credentialmanager.c
    base64.c
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Target: openid4vp1_0.wasm
add_library(openid4vp1_0 openid4vp1_0.c dcql.c ${COMMON_LIB_SRCS})
set_target_properties(openid4vp1_0 PROPERTIES SUFFIX ".wasm")

# Target: issuance_provision.wasm
add_library(issuance_provision issuance/provision.c dcql.c ${COMMON_LIB_SRCS})
set_target_properties(issuance_provision PROPERTIES SUFFIX ".wasm")

# Target: pnv_openid4vp1_0.wasm
add_library(pnv_openid4vp1_0 pnv/openid4vp1_0.c pnv/dcql.c ${COMMON_LIB_SRCS})
set_target_properties(pnv_openid4vp1_0 PROPERTIES SUFFIX ".wasm")

# Native library for testing
add_library(pnv_openid4vp1_0_native pnv/openid4vp1_0.c pnv/dcql.c ${COMMON_LIB_SRCS})

# Googletest setup
enable_testing()

find_package(doctest REQUIRED)

# Test for pnv/openid4vp1_0
add_executable(pnv_openid4vp1_0_test pnv/test/openid4vp1_0_test.cpp pnv/test/common.cpp)
target_link_libraries(pnv_openid4vp1_0_test PRIVATE doctest::doctest pnv_openid4vp1_0_native)
add_test(NAME pnv_openid4vp1_0_test COMMAND pnv_openid4vp1_0_test)

