/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "library/spdm_common_lib.h"

/**
 * Get the SPDM signing context string, which is required since SPDM 1.2.
 *
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  context_size                         SPDM signing context size
 **/
static const void *libspdm_auth_get_signing_context_string (
    size_t *context_size)
{
    *context_size = SPDM_AUTH_USAP_SIGN_CONTEXT_SIZE;
    return SPDM_AUTH_USAP_SIGN_CONTEXT;
}

uint32_t libspdm_auth_base_algo_to_spdm_base_asym_algo (
    uint64_t auth_base_algo
    )
{
    switch(auth_base_algo) {
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    case SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256;
    case SPDM_AUTH_BASE_ASYM_ALGO_EDDSA_ED25519:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519;
    case SPDM_AUTH_BASE_ASYM_ALGO_EDDSA_ED448:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    default:
        LIBSPDM_ASSERT(false);
        return 0;
    }
}

uint32_t libspdm_auth_base_hash_algo_to_spdm_base_hash_algo (
    uint64_t auth_base_hash_algo
    )
{
    switch(auth_base_hash_algo) {
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_384:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_512:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256;
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384;
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    case SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SM3_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    default:
        LIBSPDM_ASSERT(false);
        return 0;
    }
}

uint32_t libspdm_auth_get_asym_signature_size(uint64_t auth_base_algo)
{
    uint32_t base_asym_algo;

    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    return libspdm_get_asym_signature_size(base_asym_algo);
}

/**
 * Create SPDM signing context, which is required since SPDM 1.2.
 *
 * @param  spdm_version                         negotiated SPDM version
 * @param  op_code                              the SPDM opcode which requires the signing
 * @param  is_requester                         indicate if the signing is from a requester
 * @param  spdm_signing_context                 SPDM signing context
 **/
static void libspdm_auth_create_signing_context (
    spdm_auth_version_number_t spdm_auth_version,
    void *spdm_auth_signing_context)
{
    size_t index;
    char *context_str;

    /* So far, it only leaves 1 bytes for version*/
    LIBSPDM_ASSERT((((spdm_auth_version >> 12) & 0xF) < 10) &&
                   (((spdm_auth_version >> 8) & 0xF) < 10));

    context_str = spdm_auth_signing_context;
    for (index = 0; index < 4; index++) {
        libspdm_copy_mem(context_str,
                         SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT_SIZE,
                         SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT,
                         SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT_SIZE);
        /* patch the version*/
        context_str[11] = (char)('0' + ((spdm_auth_version >> 12) & 0xF));
        context_str[13] = (char)('0' + ((spdm_auth_version >> 8) & 0xF));
        context_str[15] = (char)('*');
        context_str += SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT_SIZE;
    }

    libspdm_zero_mem (
        context_str,
        36 - SPDM_AUTH_USAP_SIGN_CONTEXT_SIZE);
    libspdm_copy_mem(
        context_str + (36 - SPDM_AUTH_USAP_SIGN_CONTEXT_SIZE),
        SPDM_AUTH_USAP_SIGN_CONTEXT_SIZE,
        SPDM_AUTH_USAP_SIGN_CONTEXT,
        SPDM_AUTH_USAP_SIGN_CONTEXT_SIZE);
    return;
}

bool libspdm_auth_asym_verify(
    spdm_auth_version_number_t spdm_auth_version,
    uint64_t auth_base_algo, uint64_t auth_base_hash_algo,
    void *context,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm_auth_signing_context_with_hash[SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE +
                                                LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;

    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    base_hash_algo = libspdm_auth_base_hash_algo_to_spdm_base_hash_algo(auth_base_hash_algo);

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    param = NULL;
    param_size = 0;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        param = "";
        param_size = 0;
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        hash_nid = LIBSPDM_CRYPTO_NID_NULL;
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        hash_nid = LIBSPDM_CRYPTO_NID_NULL;
        param = libspdm_auth_get_signing_context_string (&param_size);
        break;
    default:
        /* pass thru for rest algorithm */
        break;
    }

    libspdm_auth_create_signing_context (spdm_auth_version,
                                         spdm_auth_signing_context_with_hash);
    hash_size = libspdm_get_hash_size(base_hash_algo);
    result = libspdm_hash_all(base_hash_algo, message, message_size,
                              &spdm_auth_signing_context_with_hash[
                                  SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE]);
    if (!result) {
        return false;
    }

    /* re-assign message and message_size for signing */
    message = spdm_auth_signing_context_with_hash;
    message_size = SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE + hash_size;

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size, message_hash);
        if (!result) {
            return false;
        }
        result = libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                          param, param_size,
                                          message_hash, hash_size,
                                          signature, sig_size);
    } else {
        result = libspdm_asym_verify_wrap(context, hash_nid, base_asym_algo,
                                          param, param_size,
                                          message, message_size,
                                          signature, sig_size);
    }

    return result;
}

bool libspdm_auth_asym_sign(
    spdm_auth_version_number_t spdm_auth_version,
    uint64_t auth_base_algo, uint64_t auth_base_hash_algo,
    void *context,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    bool need_hash;
    uint8_t message_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
    size_t hash_nid;
    uint8_t spdm_auth_signing_context_with_hash[SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE +
                                                LIBSPDM_MAX_HASH_SIZE];
    const void *param;
    size_t param_size;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;

    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    base_hash_algo = libspdm_auth_base_hash_algo_to_spdm_base_hash_algo(auth_base_hash_algo);

    hash_nid = libspdm_get_hash_nid(base_hash_algo);
    need_hash = libspdm_asym_func_need_hash(base_asym_algo);

    param = NULL;
    param_size = 0;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        param = "";
        param_size = 0;
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        hash_nid = LIBSPDM_CRYPTO_NID_NULL;
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        hash_nid = LIBSPDM_CRYPTO_NID_NULL;
        param = libspdm_auth_get_signing_context_string (&param_size);
        break;
    default:
        /* pass thru for rest algorithm */
        break;
    }

    libspdm_auth_create_signing_context (spdm_auth_version,
                                         spdm_auth_signing_context_with_hash);
    hash_size = libspdm_get_hash_size(base_hash_algo);
    result = libspdm_hash_all(base_hash_algo, message, message_size,
                              &spdm_auth_signing_context_with_hash[
                                  SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE]);
    if (!result) {
        return false;
    }

    /* re-assign message and message_size for signing */
    message = spdm_auth_signing_context_with_hash;
    message_size = SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE + hash_size;

    if (need_hash) {
        hash_size = libspdm_get_hash_size(base_hash_algo);
        result = libspdm_hash_all(base_hash_algo, message, message_size, message_hash);
        if (!result) {
            return false;
        }
        return libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                      param, param_size,
                                      message_hash, hash_size,
                                      signature, sig_size);
    } else {
        return libspdm_asym_sign_wrap(context, hash_nid, base_asym_algo,
                                      param, param_size,
                                      message, message_size,
                                      signature, sig_size);
    }
}

bool libspdm_auth_asym_get_public_key_from_x509(uint64_t auth_base_algo,
                                                const uint8_t *cert,
                                                size_t cert_size,
                                                void **context)
{
    uint32_t base_asym_algo;
    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    return libspdm_asym_get_public_key_from_x509(base_asym_algo, cert, cert_size, context);
}

bool libspdm_auth_asym_get_public_key_from_der(uint64_t auth_base_algo,
                                               const uint8_t *der_data,
                                               size_t der_size,
                                               void **context)
{
    uint32_t base_asym_algo;
    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    return libspdm_asym_get_public_key_from_der(base_asym_algo, der_data, der_size, context);
}

void libspdm_auth_asym_free(uint64_t auth_base_algo, void *context)
{
    uint32_t base_asym_algo;
    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    libspdm_asym_free(base_asym_algo, context);
}
