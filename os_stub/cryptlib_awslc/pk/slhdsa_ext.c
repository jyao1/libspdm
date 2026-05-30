/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SLH-DSA extended operations wrapper implementation for AWS-LC.
 *
 * SLH-DSA is NOT supported by AWS-LC. All functions return false.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"

#if LIBSPDM_SLH_DSA_SUPPORT

#include <openssl/evp.h>

extern size_t libspdm_slhdsa_type_name_to_nid(const char *type_name);

/**
 * Sets the private key component into the established SLH-DSA context.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    return false;
}

/**
 * Carries out the SLH-DSA signature generation.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_sign(void *dsa_context,
                         const uint8_t *context, size_t context_size,
                         const uint8_t *message, size_t message_size,
                         uint8_t *signature, size_t *sig_size)
{
    return false;
}

#if LIBSPDM_FIPS_MODE
/**
 * Carries out the SLH-DSA signature generation for FIPS test.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_sign_ex(void *dsa_context,
                            const uint8_t *context, size_t context_size,
                            const uint8_t *message, size_t message_size,
                            uint8_t *signature, size_t *sig_size,
                            bool deterministic)
{
    return false;
}
#endif /* LIBSPDM_FIPS_MODE */

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
