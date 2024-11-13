cmake_minimum_required(VERSION 3.5)

add_executable(test_crypt_oqs)

target_include_directories(test_crypt_oqs
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/test_crypt_oqs
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/oqslib/include
)

target_sources(test_crypt_oqs
    PRIVATE
        test_crypt_oqs.c
        kem_verify.c
        sig_verify.c
        os_support.c
)

target_link_libraries(test_crypt_oqs
    PRIVATE
        memlib
        debuglib
        rnglib
        oqslib
        malloclib
)
