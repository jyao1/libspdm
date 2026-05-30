/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Edwards-Curve Wrapper Implementation for AWS-LC.
 *
 * NOTE: Adapted from the OpenSSL wrapper. AWS-LC supports Ed25519 and Ed448
 * via EVP_PKEY_new_raw_public_key / EVP_PKEY_new_raw_private_key and
 * EVP_DigestSign/EVP_DigestVerify.
 *
 * RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)

#include <openssl/evp.h>

/**
 * Allocates and Initializes one Edwards-Curve context for subsequent use
 * with the NID.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Edwards-Curve context that has been initialized.
 *         If the allocations fails, libspdm_ecd_new_by_nid() returns NULL.
 **/
void *libspdm_ecd_new_by_nid(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    int32_t result;
    int pkey_type;
    libspdm_key_context *ecd_context;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_EDDSA_ED25519:
        pkey_type = EVP_PKEY_ED25519;
        break;
    case LIBSPDM_CRYPTO_NID_EDDSA_ED448:
        pkey_type = EVP_PKEY_ED448;
        break;
    default:
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(pkey_type, NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }
    result = EVP_PKEY_keygen_init(pkey_ctx);
    if (result <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    pkey = NULL;
    result = EVP_PKEY_keygen(pkey_ctx, &pkey);
    if (result <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    /* Allocate key context wrapper */
    ecd_context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ecd_context == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ecd_context->evp_pkey = pkey;
    return ecd_context;
}

/**
 * Release the specified Ed context.
 *
 * @param[in]  ecd_context  Pointer to the Ed context to be released.
 **/
void libspdm_ecd_free(void *ecd_context)
{
    libspdm_key_context *key_ctx;

    if (ecd_context == NULL) {
        return;
    }

    key_ctx = (libspdm_key_context *)ecd_context;
    if (key_ctx->evp_pkey != NULL) {
        EVP_PKEY_free(key_ctx->evp_pkey);
    }
    free(key_ctx);
}

/**
 * Sets the public key component into the established Ed context.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[in]       public_key       Pointer to the buffer containing the public key.
 * @param[in]       public_key_size  The size of public buffer in bytes.
 *
 * @retval  true   Ed public key component was set successfully.
 * @retval  false  Invalid Ed public key component.
 **/
bool libspdm_ecd_set_pub_key(void *ecd_context, const uint8_t *public_key,
                             size_t public_key_size)
{
    libspdm_key_context *key_ctx;
    uint32_t final_pub_key_size;
    EVP_PKEY *evp_key;
    EVP_PKEY *new_evp_key;

    if ((ecd_context == NULL) || (public_key == NULL)) {
        return false;
    }

    key_ctx = (libspdm_key_context *)ecd_context;
    evp_key = key_ctx->evp_pkey;
    if (evp_key == NULL) {
        return false;
    }

    switch (EVP_PKEY_id(evp_key)) {
    case EVP_PKEY_ED25519:
        final_pub_key_size = 32;
        break;
    case EVP_PKEY_ED448:
        final_pub_key_size = 57;
        break;
    default:
        return false;
    }

    if (final_pub_key_size != public_key_size) {
        return false;
    }

    new_evp_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_id(evp_key), NULL,
                                              public_key, public_key_size);

    if (new_evp_key == NULL) {
        return false;
    }

    /* Replace the old key with the new one */
    EVP_PKEY_free(evp_key);
    key_ctx->evp_pkey = new_evp_key;

    return true;
}

/**
 * Sets the private key component into the established Ed context.
 *
 * For ed25519, the private_size is 32.
 * For ed448, the private_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[in]       private_key      Pointer to the buffer containing the private key.
 * @param[in]       private_key_size The size of private buffer in bytes.
 *
 * @retval  true   Ed private key component was set successfully.
 * @retval  false  Invalid Ed private key component.
 **/
bool libspdm_ecd_set_pri_key(void *ecd_context, const uint8_t *private_key,
                             size_t private_key_size)
{
    libspdm_key_context *key_ctx;
    uint32_t final_pri_key_size;
    EVP_PKEY *evp_key;
    EVP_PKEY *new_evp_key;

    if ((ecd_context == NULL) || (private_key == NULL)) {
        return false;
    }

    key_ctx = (libspdm_key_context *)ecd_context;
    evp_key = key_ctx->evp_pkey;
    if (evp_key == NULL) {
        return false;
    }

    switch (EVP_PKEY_id(evp_key)) {
    case EVP_PKEY_ED25519:
        final_pri_key_size = 32;
        break;
    case EVP_PKEY_ED448:
        final_pri_key_size = 57;
        break;
    default:
        return false;
    }

    if (final_pri_key_size != private_key_size) {
        return false;
    }

    new_evp_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_id(evp_key), NULL,
                                               private_key, private_key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    /* Replace the old key with the new one */
    EVP_PKEY_free(evp_key);
    key_ctx->evp_pkey = new_evp_key;

    return true;
}

/**
 * Gets the public key component from the established Ed context.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[out]      public_key       Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size  On input, the size of public buffer in bytes.
 *                                   On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   Ed key component was retrieved successfully.
 * @retval  false  Invalid Ed public key component.
 **/
bool libspdm_ecd_get_pub_key(void *ecd_context, uint8_t *public_key,
                             size_t *public_key_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    int32_t result;
    uint32_t final_pub_key_size;

    if (ecd_context == NULL || public_key == NULL ||
        public_key_size == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)ecd_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_ED25519:
        final_pub_key_size = 32;
        break;
    case EVP_PKEY_ED448:
        final_pub_key_size = 57;
        break;
    default:
        return false;
    }
    if (*public_key_size < final_pub_key_size) {
        *public_key_size = final_pub_key_size;
        return false;
    }
    *public_key_size = final_pub_key_size;
    libspdm_zero_mem(public_key, *public_key_size);
    result = EVP_PKEY_get_raw_public_key(pkey, public_key, public_key_size);
    if (result == 0) {
        return false;
    }

    return true;
}

/**
 * Validates key components of Ed context.
 *
 * @param[in]  ecd_context  Pointer to Ed context to check.
 *
 * @retval  true   Ed key components are valid.
 * @retval  false  Ed key components are not valid.
 **/
bool libspdm_ecd_check_key(const void *ecd_context)
{
    /* AWS-LC does not provide a separate Ed key check API */
    if (ecd_context == NULL) {
        return false;
    }

    libspdm_key_context *key_ctx = (libspdm_key_context *)ecd_context;
    if (key_ctx->evp_pkey == NULL) {
        return false;
    }

    int pkey_id = EVP_PKEY_id(key_ctx->evp_pkey);
    if (pkey_id != EVP_PKEY_ED25519 && pkey_id != EVP_PKEY_ED448) {
        return false;
    }

    return true;
}

/**
 * Generates Ed key and returns Ed public key.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to the Ed context.
 * @param[out]      public_key       Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size  On input, the size of public buffer in bytes.
 *                                   On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   Ed public key generation succeeded.
 * @retval false  Ed public key generation failed.
 * @retval false  public_key_size is not large enough.
 **/
bool libspdm_ecd_generate_key(void *ecd_context, uint8_t *public_key,
                              size_t *public_key_size)
{
    /* Key is already generated at new time */
    return libspdm_ecd_get_pub_key(ecd_context, public_key, public_key_size);
}

/**
 * Carries out the Ed-DSA signature.
 *
 * This function carries out the Ed-DSA signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.
 *
 * @param[in]       ecd_context    Pointer to Ed context for signature generation.
 * @param[in]       hash_nid       hash NID
 * @param[in]       context        the EDDSA signing context.
 * @param[in]       context_size   size of EDDSA signing context.
 * @param[in]       message        Pointer to octet message to be signed (before hash).
 * @param[in]       size           size of the message in bytes.
 * @param[out]      signature      Pointer to buffer to receive Ed-DSA signature.
 * @param[in, out]  sig_size       On input, the size of signature buffer in bytes.
 *                                 On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in Ed-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_eddsa_sign(const void *ecd_context, size_t hash_nid,
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t size, uint8_t *signature,
                        size_t *sig_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;

    if (ecd_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    key_ctx = (libspdm_key_context *)ecd_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_ED25519:
        half_size = 32;
        break;
    case EVP_PKEY_ED448:
        half_size = 57;
        break;
    default:
        return false;
    }
    if (*sig_size < (size_t)(half_size * 2)) {
        *sig_size = half_size * 2;
        return false;
    }
    *sig_size = half_size * 2;
    libspdm_zero_mem(signature, *sig_size);

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_NULL:
        break;
    default:
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    /* AWS-LC uses EVP_DigestSignInit with NULL md for EdDSA */
    result = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestSign(ctx, signature, sig_size, message, size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

/**
 * Verifies the Ed-DSA signature.
 *
 * For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.
 *
 * @param[in]  ecd_context    Pointer to Ed context for signature verification.
 * @param[in]  hash_nid       hash NID
 * @param[in]  context        the EDDSA signing context.
 * @param[in]  context_size   size of EDDSA signing context.
 * @param[in]  message        Pointer to octet message to be checked (before hash).
 * @param[in]  size           size of the message in bytes.
 * @param[in]  signature      Pointer to Ed-DSA signature to be verified.
 * @param[in]  sig_size       size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in Ed-DSA.
 * @retval  false  Invalid signature or invalid Ed context.
 **/
bool libspdm_eddsa_verify(const void *ecd_context, size_t hash_nid,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t size,
                          const uint8_t *signature, size_t sig_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;

    if (ecd_context == NULL || message == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    key_ctx = (libspdm_key_context *)ecd_context;
    pkey = key_ctx->evp_pkey;
    if (pkey == NULL) {
        return false;
    }
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_ED25519:
        half_size = 32;
        break;
    case EVP_PKEY_ED448:
        half_size = 57;
        break;
    default:
        return false;
    }
    if (sig_size != (size_t)(half_size * 2)) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_NULL:
        break;
    default:
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    /* AWS-LC uses EVP_DigestVerifyInit with NULL md for EdDSA */
    result = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestVerify(ctx, signature, sig_size, message, size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}
#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */
