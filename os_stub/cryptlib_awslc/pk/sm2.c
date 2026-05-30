/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Shang-Mi2 Asymmetric Wrapper Implementation.
 *
 * SM2 is NOT supported by AWS-LC. All functions return false/NULL.
 **/

#include "internal_crypt_lib.h"

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  NULL (SM2 not supported by AWS-LC).
 **/
void *libspdm_sm2_dsa_new_by_nid(size_t nid)
{
    return NULL;
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 **/
void libspdm_sm2_dsa_free(void *sm2_context)
{
}

/**
 * Sets the public key component into the established sm2 context.
 *
 * @retval  false  SM2 not supported by AWS-LC.
 **/
bool libspdm_sm2_dsa_set_pub_key(void *sm2_context, const uint8_t *public_key,
                                 size_t public_key_size)
{
    return false;
}

/**
 * Gets the public key component from the established sm2 context.
 *
 * @retval  false  SM2 not supported by AWS-LC.
 **/
bool libspdm_sm2_dsa_get_pub_key(void *sm2_context, uint8_t *public_key,
                                 size_t *public_key_size)
{
    return false;
}

/**
 * Validates key components of sm2 context.
 *
 * @retval  false  SM2 not supported by AWS-LC.
 **/
bool libspdm_sm2_dsa_check_key(const void *sm2_context)
{
    return false;
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y).
 *
 * @retval  false  SM2 not supported by AWS-LC.
 **/
bool libspdm_sm2_dsa_generate_key(void *sm2_context, uint8_t *public_data,
                                  size_t *public_size)
{
    return false;
}

/**
 * Carries out the SM2 signature.
 *
 * @retval  false  SM2 not supported by AWS-LC.
 **/
bool libspdm_sm2_dsa_sign(const void *sm2_context, size_t hash_nid,
                          const uint8_t *id_a, size_t id_a_size,
                          const uint8_t *message, size_t size,
                          uint8_t *signature, size_t *sig_size)
{
    return false;
}

/**
 * Verifies the SM2 signature.
 *
 * @retval  false  SM2 not supported by AWS-LC.
 **/
bool libspdm_sm2_dsa_verify(const void *sm2_context, size_t hash_nid,
                            const uint8_t *id_a, size_t id_a_size,
                            const uint8_t *message, size_t size,
                            const uint8_t *signature, size_t sig_size)
{
    return false;
}

/**
 * Allocates and Initializes one Shang-Mi2 key exchange context.
 *
 * @return  NULL (SM2 key exchange not supported by AWS-LC).
 **/
void *libspdm_sm2_key_exchange_new_by_nid(size_t nid)
{
    return NULL;
}

/**
 * Release the specified sm2 key exchange context.
 **/
void libspdm_sm2_key_exchange_free(void *sm2_context)
{
}

/**
 * Initialize the specified sm2 key exchange context.
 *
 * @retval  false  SM2 key exchange not supported by AWS-LC.
 **/
bool libspdm_sm2_key_exchange_init(const void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *id_b, size_t id_b_size,
                                   bool is_initiator)
{
    return false;
}

/**
 * Generates sm2 key exchange public key.
 *
 * @retval  false  SM2 key exchange not supported by AWS-LC.
 **/
bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public_data,
                                           size_t *public_size)
{
    return false;
}

/**
 * Computes exchanged common key using SM2 key exchange.
 *
 * @retval  false  SM2 key exchange not supported by AWS-LC.
 **/
bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                          const uint8_t *peer_public,
                                          size_t peer_public_size, uint8_t *key,
                                          size_t *key_size)
{
    return false;
}
