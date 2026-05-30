/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation (Extended) for AWS-LC.
 *
 * This file implements following APIs which provide more capabilities for RSA:
 * 1) libspdm_rsa_get_key
 * 2) libspdm_rsa_generate_key
 * 3) libspdm_rsa_check_key
 * 4) libspdm_rsa_pkcs1_sign_with_nid
 * 5) libspdm_rsa_pss_sign
 * 6) libspdm_rsa_pss_sign_fips
 *
 * AWS-LC (BoringSSL fork) API usage:
 * - RSA_generate_key_ex() for key generation
 * - RSA_get0_key/factors/crt_params for component extraction
 * - RSA_check_key() for key validation
 * - EVP_PKEY_CTX_new() + EVP_PKEY_sign_init() for signing
 * - EVP_sha256() etc. (no EVP_MD_fetch/EVP_MD_free)
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

/**
 * Helper: get EVP_MD from hash NID.
 * AWS-LC uses static EVP_MD objects (no fetch/free needed).
 */
static const EVP_MD *libspdm_get_evp_md(size_t hash_nid, size_t hash_size)
{
    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return NULL;
        }
        return EVP_sha256();
    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return NULL;
        }
        return EVP_sha384();
    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return NULL;
        }
        return EVP_sha512();
    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return NULL;
        }
        return EVP_sha3_256();
    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return NULL;
        }
        return EVP_sha3_384();
    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return NULL;
        }
        return EVP_sha3_512();
    default:
        return NULL;
    }
}

/**
 * Helper function to perform RSA signature with specified padding.
 *
 * @param[in]      ctx           libspdm_key_context containing EVP_PKEY
 * @param[in]      evp_md        EVP_MD to use for signature
 * @param[in]      padding       RSA padding mode (RSA_PKCS1_PADDING or RSA_PKCS1_PSS_PADDING)
 * @param[in]      salt_len      Salt length for PSS (ignored for PKCS1)
 * @param[in]      message_hash  Pointer to message hash to be signed
 * @param[in]      hash_size     Size of the message hash in bytes
 * @param[out]     signature     Pointer to buffer to receive signature
 * @param[in, out] sig_size      On input, size of signature buffer; on output, size of signature
 *
 * @retval  true   Signature generated successfully.
 * @retval  false  Signature generation failed.
 **/
static bool libspdm_rsa_sign_with_padding(libspdm_key_context *ctx, const EVP_MD *evp_md,
                                          int padding, int salt_len,
                                          const uint8_t *message_hash, size_t hash_size,
                                          uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY_CTX *pctx;
    size_t out_len;
    int rc;
    bool result;

    pctx = EVP_PKEY_CTX_new(ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    rc = EVP_PKEY_sign_init(pctx);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, padding);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_CTX_set_signature_md(pctx, evp_md);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    /* For PSS padding, set additional parameters */
    if (padding == RSA_PKCS1_PSS_PADDING) {
        rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, evp_md);
        if (rc != 1) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len);
        if (rc != 1) {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    out_len = *sig_size;
    rc = EVP_PKEY_sign(pctx, signature, &out_len, message_hash, hash_size);
    result = false;
    if (rc == 1) {
        *sig_size = out_len;
        result = true;
    }

    EVP_PKEY_CTX_free(pctx);
    return result;
}

/**
 * Gets the tag-designated RSA key component from the established RSA context.
 *
 * This function retrieves the tag-designated RSA key component from the
 * established RSA context as a non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If specified key component has not been set or has been cleared, then returned
 * bn_size is set to 0.
 * If the big_number buffer is too small to hold the contents of the key, false
 * is returned and bn_size is set to the required buffer size to obtain the key.
 *
 * If rsa_context is NULL, then return false.
 * If bn_size is NULL, then return false.
 * If bn_size is large enough but big_number is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[out]      big_number   Pointer to octet integer buffer.
 * @param[in, out]  bn_size      On input, the size of big number buffer in bytes.
 *                             On output, the size of data returned in big number
 *                             buffer in bytes.
 *
 * @retval  true   RSA key component was retrieved successfully.
 * @retval  false  Invalid RSA key component tag.
 * @retval  false  bn_size is too small.
 **/
bool libspdm_rsa_get_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         uint8_t *big_number, size_t *bn_size)
{
    libspdm_key_context *ctx;
    const RSA *rsa;
    const BIGNUM *bn_key;
    const BIGNUM *tmp_n, *tmp_e, *tmp_d;
    const BIGNUM *tmp_p, *tmp_q;
    const BIGNUM *tmp_dp, *tmp_dq, *tmp_q_inv;
    size_t size;

    if (rsa_context == NULL || bn_size == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;

    if (ctx->evp_pkey == NULL) {
        if (big_number == NULL) {
            *bn_size = 0;
            return true;
        }
        return false;
    }

    rsa = EVP_PKEY_get0_RSA(ctx->evp_pkey);
    if (rsa == NULL) {
        *bn_size = 0;
        return true;
    }

    RSA_get0_key(rsa, &tmp_n, &tmp_e, &tmp_d);
    RSA_get0_factors(rsa, &tmp_p, &tmp_q);
    RSA_get0_crt_params(rsa, &tmp_dp, &tmp_dq, &tmp_q_inv);

    bn_key = NULL;
    switch (key_tag) {
    case LIBSPDM_RSA_KEY_N:
        bn_key = tmp_n;
        break;
    case LIBSPDM_RSA_KEY_E:
        bn_key = tmp_e;
        break;
    case LIBSPDM_RSA_KEY_D:
        bn_key = tmp_d;
        break;
    case LIBSPDM_RSA_KEY_P:
        bn_key = tmp_p;
        break;
    case LIBSPDM_RSA_KEY_Q:
        bn_key = tmp_q;
        break;
    case LIBSPDM_RSA_KEY_DP:
        bn_key = tmp_dp;
        break;
    case LIBSPDM_RSA_KEY_DQ:
        bn_key = tmp_dq;
        break;
    case LIBSPDM_RSA_KEY_Q_INV:
        bn_key = tmp_q_inv;
        break;
    default:
        return false;
    }

    size = (bn_key != NULL) ? (size_t)BN_num_bytes(bn_key) : 0;

    if (big_number == NULL) {
        /* Match legacy behavior expected by unit tests:
         * - If component exists: return false and set required size
         * - If component not set: return true with size = 0 */
        if (bn_key == NULL) {
            *bn_size = 0;
            return true;
        }
        *bn_size = size;
        return false;
    }
    if (*bn_size < size) {
        *bn_size = size;
        return false;
    }
    if (bn_key == NULL) {
        *bn_size = 0;
        return true;
    }
    *bn_size = BN_bn2bin(bn_key, big_number);
    return true;
}

/**
 * Generates RSA key components.
 *
 * This function generates RSA key components. It takes RSA public exponent E and
 * length in bits of RSA modulus N as input, and generates all key components.
 * If public_exponent is NULL, the default RSA public exponent (0x10001) will be used.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context           Pointer to RSA context being set.
 * @param[in]       modulus_length        length of RSA modulus N in bits.
 * @param[in]       public_exponent       Pointer to RSA public exponent.
 * @param[in]       public_exponent_size  size of RSA public exponent buffer in bytes.
 *
 * @retval  true   RSA key component was generated successfully.
 * @retval  false  Invalid RSA key component tag.
 **/
bool libspdm_rsa_generate_key(void *rsa_context, size_t modulus_length,
                              const uint8_t *public_exponent,
                              size_t public_exponent_size)
{
    libspdm_key_context *ctx;
    RSA *rsa_key;
    EVP_PKEY *new_pkey;
    BIGNUM *bn_e;
    int ok;

    if (rsa_context == NULL || modulus_length > INT_MAX) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;

    /* Build exponent */
    if (public_exponent == NULL) {
        bn_e = BN_new();
        if (bn_e == NULL || BN_set_word(bn_e, 0x10001) != 1) {
            BN_free(bn_e);
            return false;
        }
    } else {
        if (public_exponent_size > INT_MAX) {
            return false;
        }
        bn_e = BN_bin2bn(public_exponent, (int)public_exponent_size, NULL);
        if (bn_e == NULL) {
            return false;
        }
    }

    rsa_key = RSA_new();
    if (rsa_key == NULL) {
        BN_free(bn_e);
        return false;
    }

    ok = RSA_generate_key_ex(rsa_key, (int)modulus_length, bn_e, NULL);
    BN_free(bn_e);
    if (ok != 1) {
        RSA_free(rsa_key);
        return false;
    }

    new_pkey = EVP_PKEY_new();
    if (new_pkey == NULL) {
        RSA_free(rsa_key);
        return false;
    }

    if (EVP_PKEY_assign_RSA(new_pkey, rsa_key) != 1) {
        EVP_PKEY_free(new_pkey);
        RSA_free(rsa_key);
        return false;
    }
    /* rsa_key ownership transferred to new_pkey */

    /* Clear old pkey before setting new key */
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_pkey;
    return true;
}

/**
 * Validates key components of RSA context.
 * NOTE: This function performs integrity checks on all the RSA key material, so
 *      the RSA key structure must contain all the private key data.
 *
 * This function validates key components of RSA context in following aspects:
 * - Whether p is a prime
 * - Whether q is a prime
 * - Whether n = p * q
 * - Whether d*e = 1  mod lcm(p-1,q-1)
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in]  rsa_context  Pointer to RSA context to check.
 *
 * @retval  true   RSA key components are valid.
 * @retval  false  RSA key components are not valid.
 **/
bool libspdm_rsa_check_key(void *rsa_context)
{
    libspdm_key_context *ctx;
    RSA *rsa;

    if (rsa_context == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }
    rsa = EVP_PKEY_get0_RSA(ctx->evp_pkey);
    if (rsa == NULL) {
        return false;
    }
    return (RSA_check_key(rsa) == 1);
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5
 * encoding scheme defined in RSA PKCS#1.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512,
 * SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      rsa_context   Pointer to RSA context for signature generation.
 * @param[in]      hash_nid      hash NID
 * @param[in]      message_hash  Pointer to octet message hash to be signed.
 * @param[in]      hash_size     size of the message hash in bytes.
 * @param[out]     signature     Pointer to buffer to receive RSA PKCS1-v1_5 signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                             On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in PKCS1-v1_5.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_rsa_pkcs1_sign_with_nid(void *rsa_context, size_t hash_nid,
                                     const uint8_t *message_hash,
                                     size_t hash_size, uint8_t *signature,
                                     size_t *sig_size)
{
    libspdm_key_context *ctx;
    const EVP_MD *evp_md;
    size_t need;

    if (rsa_context == NULL || message_hash == NULL || sig_size == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    /* Determine required signature size to match legacy behavior */
    need = (size_t)EVP_PKEY_size(ctx->evp_pkey);
    if ((signature == NULL) || (*sig_size < need)) {
        *sig_size = need;
        return false;
    }

    evp_md = libspdm_get_evp_md(hash_nid, hash_size);
    if (evp_md == NULL) {
        return false;
    }

    return libspdm_rsa_sign_with_padding(ctx, evp_md, RSA_PKCS1_PADDING, 0,
                                         message_hash, hash_size, signature, sig_size);
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS
 * encoding scheme defined in RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512,
 * SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature     Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_rsa_pss_sign(void *rsa_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          uint8_t *signature, size_t *sig_size)
{
    libspdm_key_context *ctx;
    const EVP_MD *evp_md;
    size_t need;

    if (rsa_context == NULL || message_hash == NULL || sig_size == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    /* Determine required signature size to match legacy behavior */
    need = (size_t)EVP_PKEY_size(ctx->evp_pkey);
    if ((signature == NULL) || (*sig_size < need)) {
        *sig_size = need;
        return false;
    }

    evp_md = libspdm_get_evp_md(hash_nid, hash_size);
    if (evp_md == NULL) {
        return false;
    }

    return libspdm_rsa_sign_with_padding(ctx, evp_md, RSA_PKCS1_PSS_PADDING,
                                         RSA_PSS_SALTLEN_DIGEST,
                                         message_hash, hash_size, signature, sig_size);
}

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme for FIPS test.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512,
 * SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature     Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_rsa_pss_sign_fips(void *rsa_context, size_t hash_nid,
                               const uint8_t *message_hash, size_t hash_size,
                               uint8_t *signature, size_t *sig_size)
{
    libspdm_key_context *ctx;
    const EVP_MD *evp_md;
    size_t need;

    if (rsa_context == NULL || message_hash == NULL || sig_size == NULL) {
        return false;
    }
    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    /* Determine required signature size to match legacy behavior */
    need = (size_t)EVP_PKEY_size(ctx->evp_pkey);
    if ((signature == NULL) || (*sig_size < need)) {
        *sig_size = need;
        return false;
    }

    evp_md = libspdm_get_evp_md(hash_nid, hash_size);
    if (evp_md == NULL) {
        return false;
    }

    /* salt len is 0 for FIPS */
    return libspdm_rsa_sign_with_padding(ctx, evp_md, RSA_PKCS1_PSS_PADDING, 0,
                                         message_hash, hash_size, signature, sig_size);
}
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
