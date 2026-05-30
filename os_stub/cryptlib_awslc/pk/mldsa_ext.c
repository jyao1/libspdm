/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * ML-DSA extended operations wrapper implementation for AWS-LC.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#if LIBSPDM_ML_DSA_SUPPORT

#include <openssl/evp.h>
#include <openssl/nid.h>

/**
 * Maps an AWS-LC NID to the corresponding LIBSPDM NID.
 **/
static size_t libspdm_mldsa_ext_get_spdm_nid(int awslc_nid)
{
    switch (awslc_nid) {
    case NID_MLDSA44:
        return LIBSPDM_CRYPTO_NID_ML_DSA_44;
    case NID_MLDSA65:
        return LIBSPDM_CRYPTO_NID_ML_DSA_65;
    case NID_MLDSA87:
        return LIBSPDM_CRYPTO_NID_ML_DSA_87;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Sets the private key component into the established ML-DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to ML-DSA context.
 * @param[in]       key_data     Pointer to the private key data.
 * @param[in]       key_size     Size of the private key data in bytes.
 *
 * @retval  true   ML-DSA private key was set successfully.
 * @retval  false  Invalid parameter or operation failed.
 **/
bool libspdm_mldsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    libspdm_key_context *ctx;
    int awslc_nid;
    size_t spdm_nid;
    uint32_t final_pri_key_size;
    EVP_PKEY *new_evp_key;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    awslc_nid = EVP_PKEY_pqdsa_get_type(ctx->evp_pkey);
    spdm_nid = libspdm_mldsa_ext_get_spdm_nid(awslc_nid);

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_pri_key_size = 2560;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_pri_key_size = 4032;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_pri_key_size = 4896;
        break;
    default:
        return false;
    }

    if (final_pri_key_size != key_size) {
        return false;
    }

    /* Create a new EVP_PKEY with the provided private key */
    new_evp_key = EVP_PKEY_pqdsa_new_raw_private_key(awslc_nid, key_data, key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    /* Replace the existing key with the new one */
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_evp_key;
    return true;
}

/**
 * Carries out the ML-DSA signature generation.
 *
 * @param[in]      dsa_context   Pointer to ML-DSA context for signature generation.
 * @param[in]      context       The ML-DSA signing context (not supported in AWS-LC, ignored).
 * @param[in]      context_size  Size of ML-DSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive ML-DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   Signature successfully generated.
 * @retval  false  Signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_mldsa_sign(void *dsa_context,
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t message_size,
                        uint8_t *signature, size_t *sig_size)
{
    libspdm_key_context *ctx;
    EVP_MD_CTX *md_ctx;
    int awslc_nid;
    size_t spdm_nid;
    size_t final_sig_size;
    int result;

    if (dsa_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    awslc_nid = EVP_PKEY_pqdsa_get_type(ctx->evp_pkey);
    spdm_nid = libspdm_mldsa_ext_get_spdm_nid(awslc_nid);

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_sig_size = 2420;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_sig_size = 3309;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_sig_size = 4627;
        break;
    default:
        return false;
    }
    if (*sig_size < final_sig_size) {
        *sig_size = final_sig_size;
        return false;
    }
    *sig_size = final_sig_size;
    libspdm_zero_mem(signature, *sig_size);

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }

    /* AWS-LC ML-DSA uses pure mode (no prehash), so md=NULL */
    result = EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, ctx->evp_pkey);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    result = EVP_DigestSign(md_ctx, signature, sig_size, message, message_size);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    EVP_MD_CTX_free(md_ctx);
    return true;
}

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the ML-DSA signature generation for FIPS test.
 *
 * In AWS-LC, ML-DSA signing is deterministic by default and the deterministic
 * parameter cannot be separately configured. This function behaves the same
 * as libspdm_mldsa_sign.
 *
 * @param[in]      dsa_context   Pointer to ML-DSA context for signature generation.
 * @param[in]      context       The ML-DSA signing context (not supported in AWS-LC, ignored).
 * @param[in]      context_size  Size of ML-DSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive ML-DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 * @param[in]      deterministic If true, then generate the signature in deterministic way.
 *
 * @retval  true   Signature successfully generated.
 * @retval  false  Signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_mldsa_sign_ex(void *dsa_context,
                           const uint8_t *context, size_t context_size,
                           const uint8_t *message, size_t message_size,
                           uint8_t *signature, size_t *sig_size,
                           bool deterministic)
{
    /* AWS-LC ML-DSA is deterministic by default; delegate to standard sign */
    return libspdm_mldsa_sign(dsa_context, context, context_size,
                              message, message_size, signature, sig_size);
}
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_ML_DSA_SUPPORT */
