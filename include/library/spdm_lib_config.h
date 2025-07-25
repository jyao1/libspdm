/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_LIB_CONFIG_H
#define SPDM_LIB_CONFIG_H

/* Code space optimization for optional messages.
 *
 * An Integrator of libspdm may not need all of the optional SPDM messages. The
 * LIBSPDM_ENABLE_CAPABILITY_***_CAP compile time switches allow the Integrator to enable or disable
 * capabilities and messages.
 */

/* SPDM 1.0 capabilities and messages. */
#ifndef LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CERT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
#define LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
#define LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES 1
#endif

/* SPDM 1.1 capabilities. */
#ifndef LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
#define LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
#define LIBSPDM_ENABLE_CAPABILITY_PSK_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
#define LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
#define LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP 1
#endif

/* SPDM 1.2 capabilities. */
#ifndef LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CSR_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP 1
#endif

/* SPDM 1.3 capabilities. */
#ifndef LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
#define LIBSPDM_ENABLE_CAPABILITY_MEL_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
#define LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
#define LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP
#define LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP 1
#endif

/* Includes SPDM 1.3 features for CSR messages. If enabled then LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
 * must also be enabled.
 */
#ifndef LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
#define LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX 1
#endif

/* If 1 then endpoint supports sending GET_CERTIFICATE and GET_DIGESTS requests.
 * If enabled and endpoint is a Responder then LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
 * must also be enabled.
 */
#ifndef LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
#define LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT 1
#endif

/* If 1 then endpoint supports sending CHALLENGE request.
 * If enabled and endpoint is a Responder then LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
 * must also be enabled.
 */
#ifndef LIBSPDM_SEND_CHALLENGE_SUPPORT
#define LIBSPDM_SEND_CHALLENGE_SUPPORT 1
#endif

/* If 1 then endpoint supports sending the GET_SUPPORTED_EVENT_TYPES, SUBSCRIBE_EVENT_TYPES, and
 * encapsulated EVENT_ACK messages. In addition, LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP must also be
 * 1.
 */
#ifndef LIBSPDM_EVENT_RECIPIENT_SUPPORT
#define LIBSPDM_EVENT_RECIPIENT_SUPPORT 1
#endif

/* If 1 then endpoint supports sending the GET_ENDPOINT_INFO request.
 * If enabled and endpoint is a Responder then LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
 * must also be enabled.
 */
#ifndef LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
#define LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT 1
#endif

/* When LIBSPDM_RESPOND_IF_READY_SUPPORT is 0 then
 *      - For a Requester, if the Responder sends a ResponseNotReady ERROR response then the error
 *        is immediately returned to the Integrator. The Requester cannot send a RESPOND_IF_READY
 *        request.
 *      - For a Responder, it cannot send a RESPOND_IF_READY ERROR response and does not support
 *        RESPOND_IF_READY.
 * When LIBSPDM_RESPOND_IF_READY_SUPPORT is 1 then
 *      - For a Requester, if the Responder sends a ResponseNotReady ERROR response then libspdm
 *        waits an amount of time, as specified by the RDTExponent parameter, before sending
 *        RESPOND_IF_READY.
 *      - For a Responder, if its response state is NOT_READY then it will send a ResponseNotReady
 *        ERROR response to the Requester, and will accept a subsequent RESPOND_IF_READY request.
 */
#ifndef LIBSPDM_RESPOND_IF_READY_SUPPORT
#define LIBSPDM_RESPOND_IF_READY_SUPPORT 1
#endif

/* Enables FIPS 140-3 mode. */
#ifndef LIBSPDM_FIPS_MODE
#define LIBSPDM_FIPS_MODE 0
#endif

/* Enables assertions and debug printing. When `LIBSPDM_DEBUG_ENABLE` is defined it overrides or
 * sets the values of `LIBSPDM_DEBUG_PRINT_ENABLE`, `LIBSPDM_DEBUG_ASSERT_ENABLE`, and
 * `LIBSPDM_BLOCK_ENABLE` to the value of `LIBSPDM_DEBUG_ENABLE`.
 *
 * Note that if this file is used with CMake and `DTARGET=Release` is defined, then all debugging
 * is disabled.
 */
#ifndef LIBSPDM_DEBUG_ENABLE
#define LIBSPDM_DEBUG_ENABLE 1
#endif

/* The SPDM specification allows a Responder to return up to 255 version entries in the `VERSION`
 * response to the Requester, including duplicate entries. For a Requester this value specifies the
 * maximum number of entries that libspdm will tolerate in a `VERSION` response before returning an
 * error. A similar macro, `SPDM_MAX_VERSION_COUNT`, exists for the Responder. However this macro
 * is not meant to be configured by the Integrator.
 */
#ifndef LIBSPDM_MAX_VERSION_COUNT
#define LIBSPDM_MAX_VERSION_COUNT 5
#endif

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
/* This value specifies the maximum size, in bytes, of the `PSK_EXCHANGE.RequesterContext` and,
 * if supported by the Responder, `PSK_EXCHANGE_RSP.ResponderContext` fields. The fields are
 * typically random or monotonically increasing numbers.
 */
#ifndef LIBSPDM_PSK_CONTEXT_LENGTH
#define LIBSPDM_PSK_CONTEXT_LENGTH LIBSPDM_MAX_HASH_SIZE
#endif

/* This value specifies the maximum size, in bytes, of the `PSK_EXCHANGE.PSKHint` field. */
#ifndef LIBSPDM_PSK_MAX_HINT_LENGTH
#define LIBSPDM_PSK_MAX_HINT_LENGTH 32
#endif
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

/* libspdm allows an Integrator to specify multiple root certificates as trust anchors when
 * verifying certificate chains from an endpoint. This value specifies the maximum number of root
 * certificates that libspdm can support.
 */
#ifndef LIBSPDM_MAX_ROOT_CERT_SUPPORT
#define LIBSPDM_MAX_ROOT_CERT_SUPPORT 10
#endif

/* If the Responder supports it a Requester is allowed to establish multiple secure sessions with
 * the Responder. This value specifies the maximum number of sessions libspdm can support.
 */
#ifndef LIBSPDM_MAX_SESSION_COUNT
#define LIBSPDM_MAX_SESSION_COUNT 4
#endif

/* This value specifies the maximum size, in bytes, of a certificate chain that can be stored in a
 * libspdm context.
 */
#ifndef LIBSPDM_MAX_CERT_CHAIN_SIZE
/* MLDSA - 0x8000, SLHDSA - 0x28000 */
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x28000
#endif

#ifndef LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE
#define LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE 0x1000
#endif

/* Partial certificates can be retrieved from a Requester or Responder and through multiple messages
 * the complete certificate chain can be constructed. This value specifies the maximum size,
 * in bytes, of a partial certificate that can be sent or received.
 */
#ifndef LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
#define LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN 1024
#endif

/* Partial measurement extension log (MEL) can be retrieved from a Responder and through multiple
 * messages the complete MEL can be constructed. This value specifies the maximum size, in bytes, of
 * a partial MEL that can be sent or received.
 */
#ifndef LIBSPDM_MAX_MEL_BLOCK_LEN
#define LIBSPDM_MAX_MEL_BLOCK_LEN 1024
#endif

/* To ensure integrity in communication between the Requester and the Responder libspdm calculates
 * cryptographic digests and signatures over multiple requests and responses. This value specifies
 * whether libspdm will use a running calculation over the transcript, where requests and responses
 * are discarded as they are cryptographically consumed, or whether libspdm will buffer the entire
 * transcript before calculating the digest or signature.
 *
 * When LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is 0 then a running calculation is used and less
 * memory is needed.
 * When LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is 1 then the entire transcript is buffered and more
 * memory is needed.
 */
#ifndef LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 0
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT

/* This value specifies the maximum size, in bytes, of a endpoint info that can be stored in a
 * libspdm context.
 */
#ifndef LIBSPDM_MAX_ENDPOINT_INFO_LENGTH
#define LIBSPDM_MAX_ENDPOINT_INFO_LENGTH 1024
#endif

#endif /* LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT */

/* Cryptography Configuration
 * In each category, at least one should be selected.
 * NOTE: Not all combination can be supported. E.g. Don't mix NIST algo with SMx.*/

#ifndef LIBSPDM_RSA_SSA_2048_SUPPORT
#define LIBSPDM_RSA_SSA_2048_SUPPORT 1
#endif
#ifndef LIBSPDM_RSA_SSA_3072_SUPPORT
#define LIBSPDM_RSA_SSA_3072_SUPPORT 1
#endif
#ifndef LIBSPDM_RSA_SSA_4096_SUPPORT
#define LIBSPDM_RSA_SSA_4096_SUPPORT 1
#endif

#ifndef LIBSPDM_RSA_PSS_2048_SUPPORT
#define LIBSPDM_RSA_PSS_2048_SUPPORT 1
#endif
#ifndef LIBSPDM_RSA_PSS_3072_SUPPORT
#define LIBSPDM_RSA_PSS_3072_SUPPORT 1
#endif
#ifndef LIBSPDM_RSA_PSS_4096_SUPPORT
#define LIBSPDM_RSA_PSS_4096_SUPPORT 1
#endif

#ifndef LIBSPDM_ECDSA_P256_SUPPORT
#define LIBSPDM_ECDSA_P256_SUPPORT 1
#endif
#ifndef LIBSPDM_ECDSA_P384_SUPPORT
#define LIBSPDM_ECDSA_P384_SUPPORT 1
#endif
#ifndef LIBSPDM_ECDSA_P521_SUPPORT
#define LIBSPDM_ECDSA_P521_SUPPORT 1
#endif

#ifndef LIBSPDM_SM2_DSA_P256_SUPPORT
#define LIBSPDM_SM2_DSA_P256_SUPPORT 1
#endif

#ifndef LIBSPDM_EDDSA_ED25519_SUPPORT
#define LIBSPDM_EDDSA_ED25519_SUPPORT 1
#endif
#ifndef LIBSPDM_EDDSA_ED448_SUPPORT
#define LIBSPDM_EDDSA_ED448_SUPPORT 1
#endif

#ifndef LIBSPDM_FFDHE_2048_SUPPORT
#define LIBSPDM_FFDHE_2048_SUPPORT 1
#endif
#ifndef LIBSPDM_FFDHE_3072_SUPPORT
#define LIBSPDM_FFDHE_3072_SUPPORT 1
#endif
#ifndef LIBSPDM_FFDHE_4096_SUPPORT
#define LIBSPDM_FFDHE_4096_SUPPORT 1
#endif

#ifndef LIBSPDM_ECDHE_P256_SUPPORT
#define LIBSPDM_ECDHE_P256_SUPPORT 1
#endif
#ifndef LIBSPDM_ECDHE_P384_SUPPORT
#define LIBSPDM_ECDHE_P384_SUPPORT 1
#endif
#ifndef LIBSPDM_ECDHE_P521_SUPPORT
#define LIBSPDM_ECDHE_P521_SUPPORT 1
#endif

#ifndef LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT
#define LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT 1
#endif

#ifndef LIBSPDM_AEAD_AES_128_GCM_SUPPORT
#define LIBSPDM_AEAD_AES_128_GCM_SUPPORT 1
#endif
#ifndef LIBSPDM_AEAD_AES_256_GCM_SUPPORT
#define LIBSPDM_AEAD_AES_256_GCM_SUPPORT 1
#endif

#ifndef LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT 1
#endif

#ifndef LIBSPDM_AEAD_SM4_128_GCM_SUPPORT
#define LIBSPDM_AEAD_SM4_128_GCM_SUPPORT 1
#endif

#ifndef LIBSPDM_SHA256_SUPPORT
#define LIBSPDM_SHA256_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA384_SUPPORT
#define LIBSPDM_SHA384_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA512_SUPPORT
#define LIBSPDM_SHA512_SUPPORT 1
#endif

#ifndef LIBSPDM_SHA3_256_SUPPORT
#define LIBSPDM_SHA3_256_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA3_384_SUPPORT
#define LIBSPDM_SHA3_384_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA3_512_SUPPORT
#define LIBSPDM_SHA3_512_SUPPORT 1
#endif

#ifndef LIBSPDM_SM3_256_SUPPORT
#define LIBSPDM_SM3_256_SUPPORT 1
#endif

#ifndef LIBSPDM_ML_DSA_44_SUPPORT
#define LIBSPDM_ML_DSA_44_SUPPORT 1
#endif

#ifndef LIBSPDM_ML_DSA_65_SUPPORT
#define LIBSPDM_ML_DSA_65_SUPPORT 1
#endif

#ifndef LIBSPDM_ML_DSA_87_SUPPORT
#define LIBSPDM_ML_DSA_87_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT
#define LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT
#define LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT
#define LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT
#define LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT
#define LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT
#define LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT
#define LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT
#define LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT
#define LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT
#define LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT
#define LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT 1
#endif

#ifndef LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT
#define LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT 1
#endif

#ifndef LIBSPDM_ML_KEM_512_SUPPORT
#define LIBSPDM_ML_KEM_512_SUPPORT 1
#endif

#ifndef LIBSPDM_ML_KEM_768_SUPPORT
#define LIBSPDM_ML_KEM_768_SUPPORT 1
#endif

#ifndef LIBSPDM_ML_KEM_1024_SUPPORT
#define LIBSPDM_ML_KEM_1024_SUPPORT 1
#endif

/* If 1 then endpoint supports parsing X.509 certificate chains. */
#ifndef LIBSPDM_CERT_PARSE_SUPPORT
#define LIBSPDM_CERT_PARSE_SUPPORT 1
#endif



/*
 * MinDataTransferSize = 42
 *
 * H = HashLen = HmacLen = [32, 64]
 * S = SigLen = [64, 512]
 * D = ExchangeDataLen = [64, 512]
 * R = RequesterContextLen >= 32
 * R = ResponderContextLen >= 0
 * O = OpaqueDataLen <= 1024
 *
 * Max Chunk No = 1, if (message size <= 42)
 * Max Chunk No = [(message size + 4) / 30] roundup, if (message size > 42)
 *
 * +==========================+==========================================+=========+
 * |  Command                 |   Size                                   |MaxChunk |
 * +==========================+==========================================+=========+
 * | GET_VERSION              | 4                                        | 1       |
 * | VERSION {1.0, 1.1, 1.2}  | 6 + 2 * 3 = 12                           | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CAPABILITIES 1.2     | 20                                       | 1       |
 * | CAPABILITIES 1.2         | 20                                       | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | ERROR                    | 4                                        | 1       |
 * | ERROR(ResponseTooLarge)  | 4 + 4 = 8                                | 1       |
 * | ERROR(LargeResponse)     | 4 + 1 = 5                                | 1       |
 * | ERROR(ResponseNotReady)  | 4 + 4 = 8                                | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | CHUNK_SEND header        | 12 + L0 (0 or 4)                         | 1       |
 * | CHUNK_RESPONSE header    | 12 + L0 (0 or 4)                         | 1       |
 * +==========================+==========================================+=========+
 * | NEGOTIATE_ALGORITHMS 1.2 | 32 + 4 * 4 = 48                          | 2       |
 * | ALGORITHMS 1.2           | 36 + 4 * 4 = 52                          | 2       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_DIGESTS 1.2          | 4                                        | 1       |
 * | DIGESTS 1.2              | 4 + H * SlotNum = [36, 516]              | [1, 18] |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CERTIFICATE 1.2      | 8                                        | 1       |
 * | CERTIFICATE 1.2          | 8 + PortionLen                           | [1, ]   |
 * +--------------------------+------------------------------------------+---------+
 * | CHALLENGE 1.2            | 40                                       | 1       |
 * | CHALLENGE_AUTH 1.2       | 38 + H * 2 + S [+ O] = [166, 678]        | [6, 23] |
 * +--------------------------+------------------------------------------+---------+
 * | GET_MEASUREMENTS 1.2     | 5 + Nonce (0 or 32)                      | 1       |
 * | MEASUREMENTS 1.2         | 42 + MeasRecLen (+ S) [+ O] = [106, 554] | [4, 19] |
 * +--------------------------+------------------------------------------+---------+
 * | KEY_EXCHANGE 1.2         | 42 + D [+ O] = [106, 554]                | [4, 19] |
 * | KEY_EXCHANGE_RSP 1.2     | 42 + D + H + S (+ H) [+ O] = [234, 1194] | [8, 40] |
 * +--------------------------+------------------------------------------+---------+
 * | FINISH 1.2               | 4 (+ S) + H = [100, 580]                 | [4, 20] |
 * | FINISH_RSP 1.2           | 4 (+ H) = [36, 69]                       | [1, 3]  |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_EXCHANGE 1.2         | 12 [+ PSKHint] + R [+ O] = 44            | 2       |
 * | PSK_EXCHANGE_RSP 1.2     | 12 + R + H (+ H) [+ O] = [108, 172]      | [4, 6]  |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_FINISH 1.2           | 4 + H = [36, 68]                         | [1, 3]  |
 * | PSK_FINISH_RSP 1.2       | 4                                        | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CSR 1.2              | 8 + RequesterInfoLen [+ O]               | [1, ]   |
 * | CSR 1.2                  | 8 + CSRLength                            | [1, ]   |
 * +--------------------------+------------------------------------------+---------+
 * | SET_CERTIFICATE 1.2      | 4 + CertChainLen                         | [1, ]   |
 * | SET_CERTIFICATE_RSP 1.2  | 4                                        | 1       |
 * +==========================+==========================================+=========+
 */

/* Enable message logging.
 * See https://github.com/DMTF/libspdm/blob/main/doc/user_guide.md#message-logging
 * for more information.
 */
#ifndef LIBSPDM_ENABLE_MSG_LOG
#define LIBSPDM_ENABLE_MSG_LOG 1
#endif

/* Enable macro checking during compilation. */
#ifndef LIBSPDM_CHECK_MACRO
#define LIBSPDM_CHECK_MACRO 0
#endif

/* Enable compilation of libspdm_check_context function. After a libspdm context has been
 * configured libspdm_check_context can be called to check that its configuration is correct.
 */
#ifndef LIBSPDM_CHECK_SPDM_CONTEXT
#define LIBSPDM_CHECK_SPDM_CONTEXT 1
#endif

/* Enable passing the SPDM context to HAL functions.
 * This macro will be removed when libspdm 4.0 is released.
 */
#ifndef LIBSPDM_HAL_PASS_SPDM_CONTEXT
#define LIBSPDM_HAL_PASS_SPDM_CONTEXT 0
#endif

/* Enable passing the SessionID to functions.
 * This macro will be removed when libspdm 4.0 is released.
 */
#ifndef LIBSPDM_PASS_SESSION_ID
#define LIBSPDM_PASS_SESSION_ID 0
#endif

/* Enable additional checks for certificates.
 * This macro will be removed when libspdm 4.0 is released.
 */
#ifndef LIBSPDM_ADDITIONAL_CHECK_CERT
#define LIBSPDM_ADDITIONAL_CHECK_CERT 0
#endif

/* Enable passing additional parameters to libspdm_write_certificate_to_nvm and libspdm_gen_csr*.
 * This macro will be removed when libspdm 4.0 is released.
 */
#ifndef LIBSPDM_SET_CERT_CSR_PARAMS
#define LIBSPDM_SET_CERT_CSR_PARAMS 0
#endif

#endif /* SPDM_LIB_CONFIG_H */
