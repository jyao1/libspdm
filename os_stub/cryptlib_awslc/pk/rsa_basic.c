/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation for AWS-LC.
 *
 * This file implements following APIs which provide basic capabilities for RSA:
 * 1) libspdm_rsa_new
 * 2) libspdm_rsa_free
 * 3) libspdm_rsa_set_key
 * 4) libspdm_rsa_pkcs1_verify_with_nid
 * 5) libspdm_rsa_pss_verify
 * 6) libspdm_rsa_pss_verify_fips
 *
 * AWS-LC (BoringSSL fork) API usage:
 * - RSA_new() + RSA_set0_key/RSA_set0_factors/RSA_set0_crt_params
 * - EVP_PKEY_new() + EVP_PKEY_assign_RSA()
 * - EVP_sha256() etc. (no EVP_MD_fetch/EVP_MD_free)
 * - EVP_PKEY_CTX_new() (no EVP_PKEY_CTX_new_from_name)
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
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

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Helper function to set RSA PSS padding parameters on a context.
 *
 * @param[in]  pctx        EVP_PKEY_CTX to configure
 * @param[in]  evp_md      EVP_MD to use for signature and MGF1
 * @param[in]  salt_len    Salt length for PSS
 *
 * @retval  true   Parameters set successfully.
 * @retval  false  Failed to set parameters.
 **/
static bool libspdm_rsa_pss_set_params(EVP_PKEY_CTX *pctx, const EVP_MD *evp_md, int salt_len)
{
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) {
        return false;
    }
    if (EVP_PKEY_CTX_set_signature_md(pctx, evp_md) != 1) {
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, evp_md) != 1) {
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len) != 1) {
        return false;
    }
    return true;
}
#endif /* LIBSPDM_RSA_PSS_SUPPORT */

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, libspdm_rsa_new() returns NULL.
 **/
void *libspdm_rsa_new(void)
{
    libspdm_key_context *ctx;

    ctx = (libspdm_key_context *)allocate_pool(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        return NULL;
    }
    libspdm_zero_mem(ctx, sizeof(*ctx));
    ctx->evp_pkey = NULL;
    return (void *)ctx;
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 **/
void libspdm_rsa_free(void *rsa_context)
{
    libspdm_key_context *ctx;

    if (rsa_context == NULL) {
        return;
    }
    ctx = (libspdm_key_context *)rsa_context;
    EVP_PKEY_free(ctx->evp_pkey);
    free_pool(ctx);
}

/**
 * Sets the tag-designated key component into the established RSA context.
 *
 * This function sets the tag-designated RSA key component into the established
 * RSA context from the user-specified non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If big_number is NULL, then the specified key component in RSA context is cleared.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[in]       big_number   Pointer to octet integer buffer.
 *                             If NULL, then the specified key component in RSA
 *                             context is cleared.
 * @param[in]       bn_size      size of big number buffer in bytes.
 *                             If big_number is NULL, then it is ignored.
 *
 * @retval  true   RSA key component was set successfully.
 * @retval  false  Invalid RSA key component tag.
 **/
bool libspdm_rsa_set_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         const uint8_t *big_number, size_t bn_size)
{
    libspdm_key_context *ctx;
    RSA *rsa_key;
    EVP_PKEY *new_pkey;
    BIGNUM *bn_n, *bn_e, *bn_d;
    BIGNUM *bn_p, *bn_q;
    BIGNUM *bn_dp, *bn_dq, *bn_q_inv;
    BIGNUM *new_bn;

    /* Check input parameters. */
    if (rsa_context == NULL || bn_size > INT_MAX) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;

    /* Handle clear operation (big_number == NULL or bn_size == 0) */
    if (big_number == NULL || bn_size == 0) {
        EVP_PKEY_free(ctx->evp_pkey);
        ctx->evp_pkey = NULL;
        return true;
    }

    /* Initialize all component pointers to NULL */
    bn_n = NULL;
    bn_e = NULL;
    bn_d = NULL;
    bn_p = NULL;
    bn_q = NULL;
    bn_dp = NULL;
    bn_dq = NULL;
    bn_q_inv = NULL;
    new_bn = NULL;
    rsa_key = NULL;
    new_pkey = NULL;

    /* Extract existing RSA components from EVP_PKEY if present */
    if (ctx->evp_pkey != NULL) {
        const RSA *existing_rsa;

        existing_rsa = EVP_PKEY_get0_RSA(ctx->evp_pkey);
        if (existing_rsa != NULL) {
            const BIGNUM *tmp_n, *tmp_e, *tmp_d;
            const BIGNUM *tmp_p, *tmp_q;
            const BIGNUM *tmp_dp, *tmp_dq, *tmp_q_inv;

            RSA_get0_key(existing_rsa, &tmp_n, &tmp_e, &tmp_d);
            if (tmp_n != NULL) {
                bn_n = BN_dup(tmp_n);
            }
            if (tmp_e != NULL) {
                bn_e = BN_dup(tmp_e);
            }
            if (tmp_d != NULL) {
                bn_d = BN_dup(tmp_d);
            }

            RSA_get0_factors(existing_rsa, &tmp_p, &tmp_q);
            if (tmp_p != NULL) {
                bn_p = BN_dup(tmp_p);
            }
            if (tmp_q != NULL) {
                bn_q = BN_dup(tmp_q);
            }

            RSA_get0_crt_params(existing_rsa, &tmp_dp, &tmp_dq, &tmp_q_inv);
            if (tmp_dp != NULL) {
                bn_dp = BN_dup(tmp_dp);
            }
            if (tmp_dq != NULL) {
                bn_dq = BN_dup(tmp_dq);
            }
            if (tmp_q_inv != NULL) {
                bn_q_inv = BN_dup(tmp_q_inv);
            }
        }
    }

    /* Convert input to BIGNUM */
    new_bn = BN_bin2bn(big_number, (int)bn_size, NULL);
    if (new_bn == NULL) {
        goto err;
    }

    /* Set the appropriate component */
    switch (key_tag) {
    case LIBSPDM_RSA_KEY_N:
        BN_free(bn_n);
        bn_n = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_E:
        BN_free(bn_e);
        bn_e = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_D:
        BN_free(bn_d);
        bn_d = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_P:
        BN_free(bn_p);
        bn_p = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_Q:
        BN_free(bn_q);
        bn_q = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_DP:
        BN_free(bn_dp);
        bn_dp = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_DQ:
        BN_free(bn_dq);
        bn_dq = new_bn;
        new_bn = NULL;
        break;
    case LIBSPDM_RSA_KEY_Q_INV:
        BN_free(bn_q_inv);
        bn_q_inv = new_bn;
        new_bn = NULL;
        break;
    default:
        goto err;
    }

    /* Build new RSA key.
     * AWS-LC/BoringSSL RSA_set0_key() requires n and e to be non-NULL on the
     * first call to a fresh RSA object. d may be NULL for public-only keys.
     * RSA_set0_factors() requires both p and q non-NULL.
     * RSA_set0_crt_params() requires all three (dp, dq, qinv) non-NULL. */
    rsa_key = RSA_new();
    if (rsa_key == NULL) {
        goto err;
    }

    /* Set n, e, d -- requires at least n and e to be present */
    if (bn_n != NULL && bn_e != NULL) {
        if (RSA_set0_key(rsa_key, bn_n, bn_e, bn_d) != 1) {
            goto err;
        }
        /* Ownership transferred to rsa_key on success */
        bn_n = NULL;
        bn_e = NULL;
        bn_d = NULL;
    } else {
        /* Cannot form a valid RSA key without at least n and e.
         * This is a partial key build (components being set one at a time).
         * We still store what we can -- just n or just e alone cannot form
         * an RSA object in AWS-LC. Store them in EVP_PKEY once both n and e
         * are available. For now, free the RSA and keep the components
         * in a temporary holding pattern by rebuilding with dummy values. */

        /* AWS-LC requires n and e together. If we only have one,
         * we cannot construct a valid RSA key yet. Return true to allow
         * incremental key construction -- the key will become usable
         * once both n and e are set. We store the partial state by
         * using a minimal placeholder. */

        /* If we have n but not e, or e but not n, we need a different approach.
         * Use a placeholder: set the missing component to BN value 0, but this
         * won't work for actual crypto. Instead, we store the BIGNUM components
         * by creating an RSA with dummy e=65537 and placeholder n=1, then
         * replacing with real values.
         *
         * Actually, the simplest correct approach for incremental building:
         * if n is NULL, create a temporary n=0; if e is NULL, create temporary e=0.
         * The key won't be usable for crypto until properly set, but it preserves
         * the components for later retrieval via rsa_get_key. */
        BIGNUM *tmp_n, *tmp_e;

        tmp_n = bn_n;
        tmp_e = bn_e;

        if (tmp_n == NULL) {
            tmp_n = BN_new();
            if (tmp_n == NULL) {
                goto err;
            }
        }
        if (tmp_e == NULL) {
            tmp_e = BN_new();
            if (tmp_e == NULL) {
                if (bn_n == NULL) {
                    BN_free(tmp_n);
                }
                goto err;
            }
        }

        if (RSA_set0_key(rsa_key, tmp_n, tmp_e, bn_d) != 1) {
            if (tmp_n != bn_n) {
                BN_free(tmp_n);
            }
            if (tmp_e != bn_e) {
                BN_free(tmp_e);
            }
            goto err;
        }
        /* Ownership transferred */
        bn_n = NULL;
        bn_e = NULL;
        bn_d = NULL;
    }

    /* Set factors p, q -- requires both to be present */
    if (bn_p != NULL && bn_q != NULL) {
        if (RSA_set0_factors(rsa_key, bn_p, bn_q) != 1) {
            goto err;
        }
        bn_p = NULL;
        bn_q = NULL;
    } else if (bn_p != NULL || bn_q != NULL) {
        /* Only one factor available -- cannot call RSA_set0_factors yet.
         * Free the lone factor since we can't store it in the RSA object. */
        BN_free(bn_p);
        bn_p = NULL;
        BN_free(bn_q);
        bn_q = NULL;
    }

    /* Set CRT params -- requires all three to be present */
    if (bn_dp != NULL && bn_dq != NULL && bn_q_inv != NULL) {
        if (RSA_set0_crt_params(rsa_key, bn_dp, bn_dq, bn_q_inv) != 1) {
            goto err;
        }
        bn_dp = NULL;
        bn_dq = NULL;
        bn_q_inv = NULL;
    } else {
        /* Partial CRT params -- cannot store in RSA object */
        BN_free(bn_dp);
        bn_dp = NULL;
        BN_free(bn_dq);
        bn_dq = NULL;
        BN_free(bn_q_inv);
        bn_q_inv = NULL;
    }

    /* Wrap RSA in EVP_PKEY */
    new_pkey = EVP_PKEY_new();
    if (new_pkey == NULL) {
        goto err;
    }

    if (EVP_PKEY_assign_RSA(new_pkey, rsa_key) != 1) {
        goto err;
    }
    rsa_key = NULL; /* ownership transferred to new_pkey */

    /* Replace old EVP_PKEY */
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_pkey;

    BN_free(new_bn);
    return true;

err:
    BN_free(new_bn);
    BN_free(bn_n);
    BN_free(bn_e);
    BN_free(bn_d);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_dp);
    BN_free(bn_dq);
    BN_free(bn_q_inv);
    RSA_free(rsa_key);
    EVP_PKEY_free(new_pkey);
    return false;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512,
 * SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature     Pointer to RSA PKCS1-v1_5 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in PKCS1-v1_5.
 * @retval  false  Invalid signature or invalid RSA context.
 **/
bool libspdm_rsa_pkcs1_verify_with_nid(void *rsa_context, size_t hash_nid,
                                       const uint8_t *message_hash,
                                       size_t hash_size, const uint8_t *signature,
                                       size_t sig_size)
{
    libspdm_key_context *ctx;
    EVP_PKEY_CTX *pctx;
    const EVP_MD *evp_md;
    int rc;
    bool result;

    /* Check input parameters. */
    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    evp_md = libspdm_get_evp_md(hash_nid, hash_size);
    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new(ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    rc = EVP_PKEY_verify_init(pctx);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_CTX_set_signature_md(pctx, evp_md);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    result = (rc == 1);

    EVP_PKEY_CTX_free(pctx);
    return result;
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512,
 * SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature     Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 **/
bool libspdm_rsa_pss_verify(void *rsa_context, size_t hash_nid,
                            const uint8_t *message_hash, size_t hash_size,
                            const uint8_t *signature, size_t sig_size)
{
    libspdm_key_context *ctx;
    EVP_PKEY_CTX *pctx;
    const EVP_MD *evp_md;
    int rc;
    bool result;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    evp_md = libspdm_get_evp_md(hash_nid, hash_size);
    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new(ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    rc = EVP_PKEY_verify_init(pctx);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    if (!libspdm_rsa_pss_set_params(pctx, evp_md, RSA_PSS_SALTLEN_DIGEST)) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    result = (rc == 1);

    EVP_PKEY_CTX_free(pctx);
    return result;
}

#if LIBSPDM_FIPS_MODE
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512,
 * SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature     Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 **/
bool libspdm_rsa_pss_verify_fips(void *rsa_context, size_t hash_nid,
                                 const uint8_t *message_hash, size_t hash_size,
                                 const uint8_t *signature, size_t sig_size)
{
    libspdm_key_context *ctx;
    EVP_PKEY_CTX *pctx;
    const EVP_MD *evp_md;
    int rc;
    bool result;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    ctx = (libspdm_key_context *)rsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    evp_md = libspdm_get_evp_md(hash_nid, hash_size);
    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new(ctx->evp_pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    rc = EVP_PKEY_verify_init(pctx);
    if (rc != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    /* salt len is 0 for FIPS test */
    if (!libspdm_rsa_pss_set_params(pctx, evp_md, 0)) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    result = (rc == 1);

    EVP_PKEY_CTX_free(pctx);
    return result;
}
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
