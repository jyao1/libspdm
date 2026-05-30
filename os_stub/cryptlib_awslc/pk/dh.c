/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Diffie-Hellman Wrapper Implementation for AWS-LC.
 *
 * NOTE: Adapted from the OpenSSL wrapper. AWS-LC maintains API compatibility
 * for DH operations using DH_new/DH_set0_pqg/EVP_PKEY.
 * Key differences from OpenSSL 3.x:
 * - No OSSL_PARAM / param_build (use DH_new + DH_set0_pqg)
 * - No EVP_PKEY_CTX_new_from_name (use EVP_PKEY_CTX_new)
 * - Use DH_get0_pub_key / DH_get0_key for key access
 *
 * RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <string.h>

#if LIBSPDM_FFDHE_SUPPORT

/* Define generator constants */
#define LIBSPDM_DH_GENERATOR_2 2
#define LIBSPDM_DH_GENERATOR_5 5

/**
 * Allocates and Initializes one Diffie-Hellman context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 *         If the allocations fails, dh_new() returns NULL.
 **/
void *libspdm_dh_new_by_nid(size_t nid)
{
    DH *dh = NULL;
    EVP_PKEY *pkey = NULL;
    libspdm_key_context *dh_context = NULL;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_FFDHE2048:
        dh = DH_get_rfc7919_2048();
        break;
    case LIBSPDM_CRYPTO_NID_FFDHE3072:
        /* AWS-LC does not support ffdhe3072 */
        return NULL;
    case LIBSPDM_CRYPTO_NID_FFDHE4096:
        dh = DH_get_rfc7919_4096();
        break;
    default:
        return NULL;
    }

    if (dh == NULL) {
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        DH_free(dh);
        return NULL;
    }

    if (EVP_PKEY_assign_DH(pkey, dh) != 1) {
        EVP_PKEY_free(pkey);
        DH_free(dh);
        return NULL;
    }
    /* dh ownership transferred to pkey */

    dh_context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (dh_context == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    dh_context->evp_pkey = pkey;
    return dh_context;
}

/**
 * Release the specified DH context.
 *
 * @param[in]  dh_context  Pointer to the DH context to be released.
 **/
void libspdm_dh_free(void *dh_context)
{
    libspdm_key_context *key_ctx;

    if (dh_context == NULL) {
        return;
    }

    key_ctx = (libspdm_key_context *)dh_context;
    if (key_ctx->evp_pkey != NULL) {
        EVP_PKEY_free(key_ctx->evp_pkey);
    }
    free(key_ctx);
}

/**
 * Generates DH parameter.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator     value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[out]      prime         Pointer to the buffer to receive the generated prime number.
 *
 * @retval true   DH parameter generation succeeded.
 * @retval false  value of generator is not supported.
 **/
bool libspdm_dh_generate_parameter(void *dh_context, size_t generator,
                                   size_t prime_length, uint8_t *prime)
{
    libspdm_key_context *key_ctx;
    DH *dh = NULL;
    EVP_PKEY *pkey;
    const BIGNUM *bn_p;
    int p_size;

    if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
        return false;
    }

    if (generator != LIBSPDM_DH_GENERATOR_2 && generator != LIBSPDM_DH_GENERATOR_5) {
        return false;
    }

    dh = DH_new();
    if (dh == NULL) {
        return false;
    }

    if (DH_generate_parameters_ex(dh, (int)prime_length, (int)generator, NULL) != 1) {
        DH_free(dh);
        return false;
    }

    DH_get0_pqg(dh, &bn_p, NULL, NULL);
    if (bn_p == NULL) {
        DH_free(dh);
        return false;
    }

    p_size = BN_bn2bin(bn_p, prime);
    if (p_size <= 0) {
        DH_free(dh);
        return false;
    }

    /* Wrap DH in EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        DH_free(dh);
        return false;
    }

    if (EVP_PKEY_assign_DH(pkey, dh) != 1) {
        EVP_PKEY_free(pkey);
        DH_free(dh);
        return false;
    }

    key_ctx = (libspdm_key_context *)dh_context;
    EVP_PKEY_free(key_ctx->evp_pkey);
    key_ctx->evp_pkey = pkey;

    return true;
}

/**
 * Sets generator and prime parameters for DH.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator     value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[in]       prime         Pointer to the prime number.
 *
 * @retval true   DH parameter setting succeeded.
 * @retval false  value of generator is not supported.
 **/
bool libspdm_dh_set_parameter(void *dh_context, size_t generator,
                              size_t prime_length, const uint8_t *prime)
{
    libspdm_key_context *key_ctx;
    DH *dh = NULL;
    EVP_PKEY *pkey;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_g = NULL;

    if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
        return false;
    }

    if (generator != LIBSPDM_DH_GENERATOR_2 && generator != LIBSPDM_DH_GENERATOR_5) {
        return false;
    }

    bn_p = BN_bin2bn(prime, (int)(prime_length / 8), NULL);
    bn_g = BN_new();
    if (bn_p == NULL || bn_g == NULL || BN_set_word(bn_g, generator) != 1) {
        BN_free(bn_p);
        BN_free(bn_g);
        return false;
    }

    dh = DH_new();
    if (dh == NULL) {
        BN_free(bn_p);
        BN_free(bn_g);
        return false;
    }

    /* DH_set0_pqg takes ownership of bn_p and bn_g on success */
    if (DH_set0_pqg(dh, bn_p, NULL, bn_g) != 1) {
        DH_free(dh);
        BN_free(bn_p);
        BN_free(bn_g);
        return false;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        DH_free(dh);
        return false;
    }

    if (EVP_PKEY_assign_DH(pkey, dh) != 1) {
        EVP_PKEY_free(pkey);
        DH_free(dh);
        return false;
    }

    key_ctx = (libspdm_key_context *)dh_context;
    EVP_PKEY_free(key_ctx->evp_pkey);
    key_ctx->evp_pkey = pkey;

    return true;
}

/**
 * Generates DH public key.
 *
 * @param[in, out]  dh_context      Pointer to the DH context.
 * @param[out]      public_key      Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size On input, the size of public_key buffer in bytes.
 *                                  On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DH public key generation succeeded.
 * @retval false  DH public key generation failed.
 * @retval false  public_key_size is not large enough.
 **/
bool libspdm_dh_generate_key(void *dh_context, uint8_t *public_key,
                             size_t *public_key_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *evp_pkey;
    DH *dh;
    const BIGNUM *pub_key_bn;
    size_t final_pub_key_size;
    int size;

    if (dh_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    key_ctx = (libspdm_key_context *)dh_context;
    evp_pkey = key_ctx->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    dh = (DH *)EVP_PKEY_get0_DH(evp_pkey);
    if (dh == NULL) {
        return false;
    }

    /* Determine expected key size from DH size */
    final_pub_key_size = (size_t)DH_size(dh);

    if (*public_key_size < final_pub_key_size) {
        *public_key_size = final_pub_key_size;
        return false;
    }

    /* Generate key pair */
    if (DH_generate_key(dh) != 1) {
        return false;
    }

    /* Extract public key */
    DH_get0_key(dh, &pub_key_bn, NULL);
    if (pub_key_bn == NULL) {
        return false;
    }

    size = BN_num_bytes(pub_key_bn);
    if (size <= 0 || (size_t)size > final_pub_key_size) {
        return false;
    }

    if (public_key != NULL) {
        libspdm_zero_mem(public_key, *public_key_size);
        BN_bn2bin(pub_key_bn, &public_key[final_pub_key_size - size]);
    }

    *public_key_size = final_pub_key_size;
    return true;
}

/**
 * Computes exchanged common key.
 *
 * @param[in, out]  dh_context          Pointer to the DH context.
 * @param[in]       peer_public_key     Pointer to the peer's public key.
 * @param[in]       peer_public_key_size size of peer's public key in bytes.
 * @param[out]      key                 Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                      On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DH exchanged key generation succeeded.
 * @retval false  DH exchanged key generation failed.
 * @retval false  key_size is not large enough.
 **/
bool libspdm_dh_compute_key(void *dh_context, const uint8_t *peer_public_key,
                            size_t peer_public_key_size, uint8_t *key,
                            size_t *key_size)
{
    libspdm_key_context *key_ctx;
    EVP_PKEY *evp_pkey;
    DH *dh;
    BIGNUM *peer_pub_bn = NULL;
    size_t final_key_size;
    int secret_len;

    if (dh_context == NULL || peer_public_key == NULL || key_size == NULL ||
        key == NULL) {
        return false;
    }

    if (peer_public_key_size > INT_MAX) {
        return false;
    }

    key_ctx = (libspdm_key_context *)dh_context;
    evp_pkey = key_ctx->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    dh = (DH *)EVP_PKEY_get0_DH(evp_pkey);
    if (dh == NULL) {
        return false;
    }

    final_key_size = (size_t)DH_size(dh);

    if (*key_size < final_key_size) {
        *key_size = final_key_size;
        return false;
    }

    /* Convert peer public key to BIGNUM */
    peer_pub_bn = BN_bin2bn(peer_public_key, (int)peer_public_key_size, NULL);
    if (peer_pub_bn == NULL) {
        return false;
    }

    /* Compute shared secret */
    libspdm_zero_mem(key, final_key_size);
    secret_len = DH_compute_key(key, peer_pub_bn, dh);
    BN_free(peer_pub_bn);

    if (secret_len <= 0) {
        return false;
    }

    /* Pad with leading zeros if needed */
    if ((size_t)secret_len < final_key_size) {
        memmove(key + final_key_size - secret_len, key, secret_len);
        libspdm_zero_mem(key, final_key_size - secret_len);
    }

    *key_size = final_key_size;
    return true;
}

#endif /* LIBSPDM_FFDHE_SUPPORT */
