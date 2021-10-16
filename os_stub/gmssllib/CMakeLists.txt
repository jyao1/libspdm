cmake_minimum_required(VERSION 2.6)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_RC4 -DNO_MD5 -DNO_AES -DNO_DES -DNO_CHACHA20 -DNO_SHA1 -DNO_SHA2")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4459 /wd4100 /wd4244 /wd4101 /wd4701 /wd4267 /wd4706 /wd4189 /wd4457 /wd4018 /wd4703 /wd4702 /wd4700")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4013") #undefined symbol

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub/gmssllib
                    ${LIBSPDM_DIR}/os_stub/gmssllib/gmssl-v3-dev/include
)

SET(src_gmssllib
#    gmssl-v3-dev/src/aes.c
#    gmssl-v3-dev/src/aes_modes.c
    gmssl-v3-dev/src/asn1.c
    gmssl-v3-dev/src/base64.c
    gmssl-v3-dev/src/block_cipher.c
#    gmssl-v3-dev/src/chacha20.c
#   gmssl-v3-dev/src/cms.c
    gmssl-v3-dev/src/debug.c
#    gmssl-v3-dev/src/des.c
    gmssl-v3-dev/src/digest.c
    gmssl-v3-dev/src/endian.h
    gmssl-v3-dev/src/gcm.c
    gmssl-v3-dev/src/gf128.c
    gmssl-v3-dev/src/hash_drbg.c
    gmssl-v3-dev/src/hex.c
    gmssl-v3-dev/src/hkdf.c
    gmssl-v3-dev/src/hmac.c
#    gmssl-v3-dev/src/md5.c
    gmssl-v3-dev/src/mem.h
#    gmssl-v3-dev/src/nginx.c
    gmssl-v3-dev/src/oid.c
#    gmssl-v3-dev/src/pbkdf2.c
    gmssl-v3-dev/src/pem.c
#    gmssl-v3-dev/src/pkcs8.c
    gmssl-v3-dev/src/rand.c
#    gmssl-v3-dev/src/rc4.c
#    gmssl-v3-dev/src/sha1.c
#    gmssl-v3-dev/src/sha256.c
#    gmssl-v3-dev/src/sha512.c
    gmssl-v3-dev/src/sm2_algo.c
    gmssl-v3-dev/src/sm2_asn1.c
    gmssl-v3-dev/src/sm2_lib.c
    gmssl-v3-dev/src/sm2_prn.c
    gmssl-v3-dev/src/sm3.c
    gmssl-v3-dev/src/sm3_hmac.c
    gmssl-v3-dev/src/sm4_common.c
    gmssl-v3-dev/src/sm4_enc.c
    gmssl-v3-dev/src/sm4_lcl.h
    gmssl-v3-dev/src/sm4_modes.c
    gmssl-v3-dev/src/sm4_setkey.c
#    gmssl-v3-dev/src/sm9_keygen.c
#    gmssl-v3-dev/src/sm9_math.c
#    gmssl-v3-dev/src/sm9_sign.c
#    gmssl-v3-dev/src/tlcp.c
#    gmssl-v3-dev/src/tls.c
#    gmssl-v3-dev/src/tls12.c
#    gmssl-v3-dev/src/tls13.c
#    gmssl-v3-dev/src/tls_trace.c
    gmssl-v3-dev/src/version.c
    gmssl-v3-dev/src/x509_algor.c
    gmssl-v3-dev/src/x509_asn1.c
#    gmssl-v3-dev/src/x509_crl.c
    gmssl-v3-dev/src/x509_ext.c
    gmssl-v3-dev/src/x509_lib.c
#    gmssl-v3-dev/src/zuc_core.c
#    gmssl-v3-dev/src/zuc_eea.c
#    gmssl-v3-dev/src/zuc_eia.c
)

ADD_LIBRARY(gmssllib STATIC ${src_gmssllib})
