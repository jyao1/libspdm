/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SLH-DSA basic operations wrapper implementation for AWS-LC.
 *
 * SLH-DSA is NOT supported by AWS-LC. All functions return false/NULL.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#if LIBSPDM_SLH_DSA_SUPPORT

#include <openssl/evp.h>
#include <string.h>

size_t libspdm_slhdsa_type_name_to_nid(const char *type_name)
{
    /* SLH-DSA not supported by AWS-LC */
    return LIBSPDM_CRYPTO_NID_NULL;
}

/**
 * Allocates and initializes one SLH-DSA context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  NULL (SLH-DSA not supported by AWS-LC).
 **/
void *libspdm_slhdsa_new(size_t nid)
{
    return NULL;
}

/**
 * Release the specified SLH-DSA context.
 **/
void libspdm_slhdsa_free(void *dsa_context)
{
    if (dsa_context == NULL) {
        return;
    }
    libspdm_key_context *ctx = (libspdm_key_context *)dsa_context;
    if (ctx->evp_pkey != NULL) {
        EVP_PKEY_free(ctx->evp_pkey);
    }
    free(ctx);
}

/**
 * Gets the public key component from the established SLH-DSA context.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size)
{
    return false;
}

/**
 * Sets the public key component into the established SLH-DSA context.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    return false;
}

/**
 * Verifies the SLH-DSA signature.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_verify(void *dsa_context,
                           const uint8_t *context, size_t context_size,
                           const uint8_t *message, size_t message_size,
                           const uint8_t *signature, size_t sig_size)
{
    return false;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
