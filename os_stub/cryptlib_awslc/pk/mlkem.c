/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * ML-KEM key encapsulation wrapper implementation for AWS-LC.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#if LIBSPDM_ML_KEM_SUPPORT

#include <openssl/evp.h>
#include <openssl/nid.h>
#include <string.h>

/**
 * Maps a LIBSPDM NID to the corresponding AWS-LC NID.
 **/
static int libspdm_mlkem_get_awslc_nid(size_t nid)
{
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        return NID_MLKEM512;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        return NID_MLKEM768;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        return NID_MLKEM1024;
    default:
        return 0;
    }
}

/**
 * Gets the LIBSPDM NID from an ML-KEM EVP_PKEY via AWS-LC API.
 **/
static size_t libspdm_mlkem_get_nid_from_pkey(EVP_PKEY *pkey)
{
    size_t pub_len;
    int ret;

    if (pkey == NULL) {
        return LIBSPDM_CRYPTO_NID_NULL;
    }

    /* Determine the NID by querying public key size */
    pub_len = 0;
    ret = EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len);
    if (ret != 1) {
        return LIBSPDM_CRYPTO_NID_NULL;
    }

    switch (pub_len) {
    case 800:
        return LIBSPDM_CRYPTO_NID_ML_KEM_512;
    case 1184:
        return LIBSPDM_CRYPTO_NID_ML_KEM_768;
    case 1568:
        return LIBSPDM_CRYPTO_NID_ML_KEM_1024;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}

/**
 * Allocates and initializes one ML-KEM context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the ML-KEM context that has been initialized.
 **/
void *libspdm_mlkem_new_by_name(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    int awslc_nid;
    int ret;
    libspdm_key_context *key_ctx;

    awslc_nid = libspdm_mlkem_get_awslc_nid(nid);
    if (awslc_nid == 0) {
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }

    ret = EVP_PKEY_CTX_kem_set_params(pkey_ctx, awslc_nid);
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

    key_ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (key_ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    key_ctx->evp_pkey = pkey;
    return (void *)key_ctx;
}

/**
 * Release the specified ML-KEM context.
 *
 * @param[in]  kem_context  Pointer to the ML-KEM context to be released.
 **/
void libspdm_mlkem_free(void *kem_context)
{
    libspdm_key_context *key_ctx;

    if (kem_context == NULL) {
        return;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    if (key_ctx->evp_pkey != NULL) {
        EVP_PKEY_free(key_ctx->evp_pkey);
    }
    free(key_ctx);
}

/**
 * Generates ML-KEM public key (encapsulation key).
 *
 * @param[in, out]  kem_context       Pointer to the ML-KEM context.
 * @param[out]      encap_key         Pointer to the buffer to receive generated public key.
 * @param[in, out]  encap_key_size    On input, the size of encap_key buffer in bytes.
 *                                    On output, the size of data returned in encap_key buffer in bytes.
 *
 * @retval true   ML-KEM public key generation succeeded.
 * @retval false  ML-KEM public key generation failed.
 * @retval false  encap_key_size is not large enough.
 **/
bool libspdm_mlkem_generate_key(void *kem_context, uint8_t *encap_key, size_t *encap_key_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    size_t spdm_nid;
    uint32_t final_encap_key_size;
    size_t out_len;
    int ret;

    if (kem_context == NULL || encap_key == NULL || encap_key_size == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    spdm_nid = libspdm_mlkem_get_nid_from_pkey(pkey);

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_encap_key_size = 800;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_encap_key_size = 1184;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_encap_key_size = 1568;
        break;
    default:
        return false;
    }

    if (*encap_key_size < final_encap_key_size) {
        *encap_key_size = final_encap_key_size;
        return false;
    }

    out_len = *encap_key_size;
    ret = EVP_PKEY_get_raw_public_key(pkey, encap_key, &out_len);
    if (ret == 0) {
        return false;
    }

    *encap_key_size = out_len;
    return true;
}

/**
 * Performs ML-KEM encapsulation.
 *
 * @param[in, out]  kem_context           Pointer to the ML-KEM context.
 * @param[in]       peer_encap_key        Pointer to the peer's public key.
 * @param[in]       peer_encap_key_size   Size of peer's public key in bytes.
 * @param[out]      cipher_text           Pointer to the buffer to receive generated cipher text.
 * @param[in, out]  cipher_text_size      On input, the size of cipher_text buffer in bytes.
 *                                        On output, the size of data returned in cipher_text buffer in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared_secret buffer in bytes.
 *                                        On output, the size of data returned in shared_secret buffer in bytes.
 *
 * @retval true   ML-KEM encapsulation succeeded.
 * @retval false  ML-KEM encapsulation failed.
 **/
bool libspdm_mlkem_encapsulate(void *kem_context, const uint8_t *peer_encap_key,
                               size_t peer_encap_key_size, uint8_t *cipher_text,
                               size_t *cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    EVP_PKEY *peer_pkey;
    EVP_PKEY_CTX *pkey_ctx;
    size_t spdm_nid;
    int awslc_nid;
    uint32_t final_encap_key_size;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;
    size_t actual_cipher_text_size;
    size_t actual_shared_secret_size;
    int ret;

    if (kem_context == NULL || peer_encap_key == NULL) {
        return false;
    }
    if (cipher_text == NULL || cipher_text_size == NULL) {
        return false;
    }
    if (shared_secret == NULL || shared_secret_size == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    spdm_nid = libspdm_mlkem_get_nid_from_pkey(pkey);
    awslc_nid = libspdm_mlkem_get_awslc_nid(spdm_nid);
    if (awslc_nid == 0) {
        return false;
    }

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_encap_key_size = 800;
        final_cipher_text_size = 768;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_encap_key_size = 1184;
        final_cipher_text_size = 1088;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_encap_key_size = 1568;
        final_cipher_text_size = 1568;
        break;
    default:
        return false;
    }
    final_shared_secret_size = 32;

    if (peer_encap_key_size != final_encap_key_size) {
        return false;
    }
    if (*cipher_text_size < final_cipher_text_size) {
        *cipher_text_size = final_cipher_text_size;
        return false;
    }
    if (*shared_secret_size < final_shared_secret_size) {
        *shared_secret_size = final_shared_secret_size;
        return false;
    }

    /* Create peer public key from raw key data */
    peer_pkey = EVP_PKEY_kem_new_raw_public_key(awslc_nid, peer_encap_key, peer_encap_key_size);
    if (peer_pkey == NULL) {
        return false;
    }

    /* Perform encapsulation using peer public key */
    pkey_ctx = EVP_PKEY_CTX_new(peer_pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    actual_cipher_text_size = *cipher_text_size;
    actual_shared_secret_size = *shared_secret_size;

    ret = EVP_PKEY_encapsulate(pkey_ctx, cipher_text, &actual_cipher_text_size,
                               shared_secret, &actual_shared_secret_size);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(peer_pkey);
        return false;
    }

    *cipher_text_size = actual_cipher_text_size;
    *shared_secret_size = actual_shared_secret_size;

    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(peer_pkey);
    return true;
}

/**
 * Performs ML-KEM decapsulation.
 *
 * @param[in, out]  kem_context           Pointer to the ML-KEM context.
 * @param[in]       peer_cipher_text      Pointer to the peer's cipher text.
 * @param[in]       peer_cipher_text_size Size of peer's cipher text in bytes.
 * @param[out]      shared_secret         Pointer to the buffer to receive generated shared secret.
 * @param[in, out]  shared_secret_size    On input, the size of shared_secret buffer in bytes.
 *                                        On output, the size of data returned in shared_secret buffer in bytes.
 *
 * @retval true   ML-KEM decapsulation succeeded.
 * @retval false  ML-KEM decapsulation failed.
 **/
bool libspdm_mlkem_decapsulate(void *kem_context, const uint8_t *peer_cipher_text,
                               size_t peer_cipher_text_size, uint8_t *shared_secret,
                               size_t *shared_secret_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pkey_ctx;
    size_t spdm_nid;
    uint32_t final_cipher_text_size;
    uint32_t final_shared_secret_size;
    size_t actual_shared_secret_size;
    int ret;

    if (kem_context == NULL || peer_cipher_text == NULL) {
        return false;
    }
    if (shared_secret == NULL || shared_secret_size == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    spdm_nid = libspdm_mlkem_get_nid_from_pkey(pkey);

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_cipher_text_size = 768;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_cipher_text_size = 1088;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_cipher_text_size = 1568;
        break;
    default:
        return false;
    }
    final_shared_secret_size = 32;

    if (peer_cipher_text_size != final_cipher_text_size) {
        return false;
    }
    if (*shared_secret_size < final_shared_secret_size) {
        *shared_secret_size = final_shared_secret_size;
        return false;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        return false;
    }

    actual_shared_secret_size = *shared_secret_size;
    ret = EVP_PKEY_decapsulate(pkey_ctx, shared_secret, &actual_shared_secret_size,
                               peer_cipher_text, peer_cipher_text_size);
    if (ret != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    *shared_secret_size = actual_shared_secret_size;
    EVP_PKEY_CTX_free(pkey_ctx);
    return true;
}

#if LIBSPDM_FIPS_MODE
/**
 * Performs ML-KEM encapsulation with entropy for FIPS test.
 *
 * AWS-LC does not expose a deterministic encapsulation API with external entropy.
 * This function is not supported.
 *
 * @retval  false  Not supported in AWS-LC.
 **/
bool libspdm_mlkem_encapsulate_ex(void *kem_context, const uint8_t *peer_encap_key,
                                  size_t peer_encap_key_size, uint8_t *cipher_text,
                                  size_t *cipher_text_size, uint8_t *shared_secret,
                                  size_t *shared_secret_size, uint8_t *entropy,
                                  size_t entropy_size)
{
    return false;
}

/**
 * Sets the private key into the established ML-KEM context.
 *
 * @param[in, out]  kem_context  Pointer to ML-KEM context.
 * @param[in]       key_data     Pointer to the private key data.
 * @param[in]       key_size     Size of the private key data in bytes.
 *
 * @retval  true   ML-KEM private key was set successfully.
 * @retval  false  Invalid parameter or operation failed.
 **/
bool libspdm_mlkem_set_privkey(void *kem_context, const uint8_t *key_data, size_t key_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    size_t spdm_nid;
    int awslc_nid;
    uint32_t final_pri_key_size;
    EVP_PKEY *new_pkey;

    if ((kem_context == NULL) || (key_data == NULL)) {
        return false;
    }

    key_ctx = (libspdm_key_context *)kem_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }

    spdm_nid = libspdm_mlkem_get_nid_from_pkey(pkey);
    awslc_nid = libspdm_mlkem_get_awslc_nid(spdm_nid);
    if (awslc_nid == 0) {
        return false;
    }

    switch (spdm_nid) {
    case LIBSPDM_CRYPTO_NID_ML_KEM_512:
        final_pri_key_size = 1632;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_768:
        final_pri_key_size = 2400;
        break;
    case LIBSPDM_CRYPTO_NID_ML_KEM_1024:
        final_pri_key_size = 3168;
        break;
    default:
        return false;
    }

    if (final_pri_key_size != key_size) {
        return false;
    }

    /* Create a new EVP_PKEY with the provided private key */
    new_pkey = EVP_PKEY_kem_new_raw_secret_key(awslc_nid, key_data, key_size);
    if (new_pkey == NULL) {
        return false;
    }

    /* Replace the existing key with the new one */
    EVP_PKEY_free(pkey);
    key_ctx->evp_pkey = new_pkey;
    return true;
}
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_ML_KEM_SUPPORT */
