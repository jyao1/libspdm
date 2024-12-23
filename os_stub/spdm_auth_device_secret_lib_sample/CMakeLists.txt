cmake_minimum_required(VERSION 3.5)

add_library(spdm_auth_device_secret_lib_sample STATIC "")

target_include_directories(spdm_auth_device_secret_lib_sample
    PRIVATE
        ${LIBSPDM_DIR}/os_stub/spdm_auth_device_secret_lib_sample
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_auth_device_secret_lib_sample
    PRIVATE
        auth_capabilities.c
        cred_id_params.c
        auth_policy.c
        ownership.c
        reset_to_default.c
        auth_sign.c
        auth_verify.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(spdm_auth_device_secret_lib_sample PRIVATE -DLIBSPDM_CPU_ARM)
endif()