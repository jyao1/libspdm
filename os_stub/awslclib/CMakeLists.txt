cmake_minimum_required(VERSION 3.5)

include(ExternalProject)

set(AWSLC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/aws-lc)
set(AWSLC_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/aws-lc-install)
set(AWSLC_LIB_DIR ${AWSLC_INSTALL_DIR}/lib)

file(MAKE_DIRECTORY ${AWSLC_INSTALL_DIR}/include)
file(MAKE_DIRECTORY ${AWSLC_LIB_DIR})

set(AWSLC_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${AWSLC_INSTALL_DIR}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DBUILD_SHARED_LIBS=OFF
    -DBUILD_TESTING=OFF
    -DDISABLE_GO=ON
    -DDISABLE_PERL=ON
)

if(CMAKE_C_COMPILER)
    list(APPEND AWSLC_CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER})
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "GCC")
        list(APPEND AWSLC_CMAKE_ARGS -G "MinGW Makefiles")
        set(AWSLC_LIB_FILE "${AWSLC_LIB_DIR}/libcrypto.a")
    else()
        list(APPEND AWSLC_CMAKE_ARGS -G "NMake Makefiles")
        set(AWSLC_LIB_FILE "${AWSLC_LIB_DIR}/crypto.lib")
    endif()
else()
    list(APPEND AWSLC_CMAKE_ARGS -G "Unix Makefiles")
    set(AWSLC_LIB_FILE "${AWSLC_LIB_DIR}/libcrypto.a")
endif()

ExternalProject_Add(
    awslc_external
    SOURCE_DIR ${AWSLC_SOURCE_DIR}
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/aws-lc-build
    CMAKE_ARGS ${AWSLC_CMAKE_ARGS}
    BUILD_ALWAYS FALSE
    INSTALL_DIR ${AWSLC_INSTALL_DIR}
    BUILD_BYPRODUCTS ${AWSLC_LIB_FILE}
)

add_library(awslclib STATIC IMPORTED GLOBAL)

set_target_properties(awslclib PROPERTIES
    IMPORTED_LOCATION ${AWSLC_LIB_FILE}
)

add_dependencies(awslclib awslc_external)

target_include_directories(awslclib
    INTERFACE
        ${AWSLC_INSTALL_DIR}/include
)
