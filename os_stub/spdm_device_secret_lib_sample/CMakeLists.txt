cmake_minimum_required(VERSION 3.5)

add_library(spdm_device_secret_lib_sample STATIC "")

target_include_directories(spdm_device_secret_lib_sample
    PRIVATE
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_device_secret_lib_sample
    PRIVATE
        chal.c
        csr.c
        csr_pqc.c
        endpointinfo.c
        event.c
        key_pair.c
        meas.c
        psk.c
        read_priv_key_pem.c
        read_priv_key_pem_pqc.c
        read_priv_key_raw_data.c
        read_priv_key_raw_data_pqc.c
        read_pub_cert.c
        read_pub_cert_pqc.c
        read_pub_key_der.c
        read_pub_key_der_pqc.c
        read_special_cert.c
        set_cert.c
        set_cert_pqc.c
        sign.c
        sign_pqc.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(spdm_device_secret_lib_sample PRIVATE -DLIBSPDM_CPU_ARM)
endif()