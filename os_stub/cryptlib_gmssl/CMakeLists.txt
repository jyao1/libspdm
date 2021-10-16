cmake_minimum_required(VERSION 2.6)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_RC4 -DNO_MD5 -DNO_AES -DNO_DES -DNO_CHACHA20 -DNO_SHA1 -DNO_SHA2")

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub/cryptlib_gmssl
                    ${LIBSPDM_DIR}/os_stub/gmssllib/include
                    ${LIBSPDM_DIR}/os_stub/gmssllib/gmssl-v3-dev/include
)

SET(src_cryptlib_gmssl
    cipher/aead_aes_gcm.c
    cipher/aead_chacha20_poly1305.c
    cipher/aead_sm4_gcm.c
    hash/sha.c
    hash/sha3.c
    hash/sm3.c
    hmac/hmac_sha.c
    hmac/hmac_sha3.c
    hmac/hmac_sm3.c
    kdf/hkdf_sha.c
    kdf/hkdf_sha3.c
    kdf/hkdf_sm3.c
    pem/pem.c
    pk/ec.c
    pk/ecd.c
    pk/ecx.c
    pk/dh.c
    pk/sm2.c
    pk/rsa_basic.c
    pk/rsa_ext.c
    pk/x509.c
    rand/rand.c
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(cryptlib_gmssl STATIC ${src_cryptlib_gmssl})
