/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * ML-DSA basic operations wrapper implementation for AWS-LC.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#if LIBSPDM_ML_DSA_SUPPORT

#include <openssl/evp.h>
#include <openssl/nid.h>
#include <string.h>

/**
 * Maps a LIBSPDM NID to the corresponding AWS-LC NID.
 **/
static int libspdm_mldsa_get_awslc_nid(size_t nid)
{
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        return NID_MLDSA44;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        return NID_MLDSA65;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        return NID_MLDSA87;
    default:
        return 0;
    }
}

/**
 * Maps an AWS-LC NID to the corresponding LIBSPDM NID.
 **/
static size_t libspdm_mldsa_get_spdm_nid(int awslc_nid)
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

size_t libspdm_mldsa_type_name_to_nid(const char *type_name)
{
    if (type_name == NULL) {
        return LIBSPDM_CRYPTO_NID_NULL;
    }
    if (strcmp(type_name, "ML-DSA-44") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_44;
    } else if (strcmp(type_name, "ML-DSA-65") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_65;
    } else if (strcmp(type_name, "ML-DSA-87") == 0) {
        return LIBSPDM_CRYPTO_NID_ML_DSA_87;
    }
    return LIBSPDM_CRYPTO_NID_NULL;
}

/**
 * Allocates and initializes one ML-DSA context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the ML-DSA context that has been initialized.
 **/
void *libspdm_mldsa_new(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    int awslc_nid;
    int ret;
    libspdm_key_context *ctx;

    awslc_nid = libspdm_mldsa_get_awslc_nid(nid);
    if (awslc_nid == 0) {
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }

    ret = EVP_PKEY_CTX_pqdsa_set_params(pkey_ctx, awslc_nid);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    ret = EVP_PKEY_keygen_init(pkey_ctx);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    pkey = NULL;
    ret = EVP_PKEY_keygen(pkey_ctx, &pkey);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ctx->evp_pkey = pkey;
    return (void *)ctx;
}

/**
 * Release the specified ML-DSA context.
 *
 * @param[in]  dsa_context  Pointer to the ML-DSA context to be released.
 **/
void libspdm_mldsa_free(void *dsa_context)
{
    libspdm_key_context *ctx;

    if (dsa_context == NULL) {
        return;
    }
    ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey != NULL) {
        EVP_PKEY_free(ctx->evp_pkey);
    }
    free(ctx);
}

/**
 * Gets the public key component from the established ML-DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to ML-DSA context.
 * @param[out]      key_data     Pointer to the buffer to receive the public key.
 * @param[in, out]  key_size     On input, the size of key_data buffer in bytes.
 *                               On output, the size of data returned in key_data buffer in bytes.
 *
 * @retval  true   ML-DSA public key was retrieved successfully.
 * @retval  false  Invalid parameter or operation failed.
 **/
bool libspdm_mldsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size)
{
    libspdm_key_context *ctx;
    int awslc_nid;
    size_t spdm_nid;
    uint32_t final_pub_key_size;
    int ret;

    if (dsa_context == NULL || key_size == NULL || key_data == NULL) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    awslc_nid = EVP_PKEY_pqdsa_get_type(ctx->evp_pkey);
    spdm_nid = libspdm_mldsa_get_spdm_nid(awslc_nid);

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_pub_key_size = 1312;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_pub_key_size = 1952;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_pub_key_size = 2592;
        break;
    default:
        return false;
    }

    if (*key_size < final_pub_key_size) {
        *key_size = final_pub_key_size;
        return false;
    }
    *key_size = final_pub_key_size;
    libspdm_zero_mem(key_data, *key_size);

    ret = EVP_PKEY_get_raw_public_key(ctx->evp_pkey, key_data, key_size);
    if (ret == 0) {
        return false;
    }

    return true;
}

/**
 * Sets the public key component into the established ML-DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to ML-DSA context.
 * @param[in]       key_data     Pointer to the public key data.
 * @param[in]       key_size     Size of the public key data in bytes.
 *
 * @retval  true   ML-DSA public key was set successfully.
 * @retval  false  Invalid parameter or operation failed.
 **/
bool libspdm_mldsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    libspdm_key_context *ctx;
    int awslc_nid;
    size_t spdm_nid;
    uint32_t final_pub_key_size;
    EVP_PKEY *new_evp_key;

    if ((dsa_context == NULL) || (key_data == NULL)) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    awslc_nid = EVP_PKEY_pqdsa_get_type(ctx->evp_pkey);
    spdm_nid = libspdm_mldsa_get_spdm_nid(awslc_nid);

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        final_pub_key_size = 1312;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        final_pub_key_size = 1952;
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        final_pub_key_size = 2592;
        break;
    default:
        return false;
    }

    if (final_pub_key_size != key_size) {
        return false;
    }

    /* Create a new EVP_PKEY with the provided public key */
    new_evp_key = EVP_PKEY_pqdsa_new_raw_public_key(awslc_nid, key_data, key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    /* Replace the existing key with the new one */
    EVP_PKEY_free(ctx->evp_pkey);
    ctx->evp_pkey = new_evp_key;
    return true;
}

/**
 * Verifies the ML-DSA signature.
 *
 * @param[in]  dsa_context   Pointer to ML-DSA context for signature verification.
 * @param[in]  context       The ML-DSA signing context (not supported in AWS-LC, ignored).
 * @param[in]  context_size  Size of ML-DSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to ML-DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid ML-DSA context.
 **/
bool libspdm_mldsa_verify(void *dsa_context,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t message_size,
                          const uint8_t *signature, size_t sig_size)
{
    libspdm_key_context *ctx;
    EVP_MD_CTX *md_ctx;
    int awslc_nid;
    size_t spdm_nid;
    size_t final_sig_size;
    int result;

    if (dsa_context == NULL || message == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey == NULL) {
        return false;
    }

    awslc_nid = EVP_PKEY_pqdsa_get_type(ctx->evp_pkey);
    spdm_nid = libspdm_mldsa_get_spdm_nid(awslc_nid);

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
    if (sig_size != final_sig_size) {
        return false;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return false;
    }

    /* AWS-LC ML-DSA uses pure mode (no prehash), so md=NULL */
    result = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, ctx->evp_pkey);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    result = EVP_DigestVerify(md_ctx, signature, sig_size, message, message_size);
    if (result != 1) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    EVP_MD_CTX_free(md_ctx);
    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
