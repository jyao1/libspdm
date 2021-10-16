/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  HMAC-SM3 Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <gmssl/sm3.h>

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SM3_256 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, hmac_sm3_256_new() returns NULL.

**/
void *hmac_sm3_256_new(void)
{
  SM3_HMAC_CTX  *sm3_hmac_ctx;

  sm3_hmac_ctx = allocate_pool (sizeof(SM3_HMAC_CTX));
  return sm3_hmac_ctx;
}

/**
  Release the specified HMAC_CTX context.

  @param[in]  hmac_sm3_256_ctx  Pointer to the HMAC_CTX context to be released.

**/
void hmac_sm3_256_free(IN void *hmac_sm3_256_ctx)
{
  free_pool (hmac_sm3_256_ctx);
}

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to hmac_sm3_256_update().

  If hmac_sm3_256_ctx is NULL, then return FALSE.

  @param[out]  hmac_sm3_256_ctx  Pointer to HMAC-SM3_256 context.
  @param[in]   key                Pointer to the user-supplied key.
  @param[in]   key_size            key size in bytes.

  @retval TRUE   The key is set successfully.
  @retval FALSE  The key is set unsuccessfully.

**/
boolean hmac_sm3_256_set_key(OUT void *hmac_sm3_256_ctx, IN const uint8 *key,
			    IN uintn key_size)
{
  sm3_hmac_init (hmac_sm3_256_ctx, key, key_size);
	return TRUE;
}

/**
  Makes a copy of an existing HMAC-SM3_256 context.

  If hmac_sm3_256_ctx is NULL, then return FALSE.
  If new_hmac_sm3_256_ctx is NULL, then return FALSE.

  @param[in]  hmac_sm3_256_ctx     Pointer to HMAC-SM3_256 context being copied.
  @param[out] new_hmac_sm3_256_ctx  Pointer to new HMAC-SM3_256 context.

  @retval TRUE   HMAC-SM3_256 context copy succeeded.
  @retval FALSE  HMAC-SM3_256 context copy failed.

**/
boolean hmac_sm3_256_duplicate(IN const void *hmac_sm3_256_ctx,
			      OUT void *new_hmac_sm3_256_ctx)
{
  copy_mem (new_hmac_sm3_256_ctx, hmac_sm3_256_ctx, sizeof(SM3_HMAC_CTX));
	return TRUE;
}

/**
  Digests the input data and updates HMAC-SM3_256 context.

  This function performs HMAC-SM3_256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SM3_256 context should be initialized by hmac_sm3_256_new(), and should not be finalized
  by hmac_sm3_256_final(). Behavior with invalid context is undefined.

  If hmac_sm3_256_ctx is NULL, then return FALSE.

  @param[in, out]  hmac_sm3_256_ctx Pointer to the HMAC-SM3_256 context.
  @param[in]       data              Pointer to the buffer containing the data to be digested.
  @param[in]       data_size          size of data buffer in bytes.

  @retval TRUE   HMAC-SM3_256 data digest succeeded.
  @retval FALSE  HMAC-SM3_256 data digest failed.

**/
boolean hmac_sm3_256_update(IN OUT void *hmac_sm3_256_ctx, IN const void *data,
			   IN uintn data_size)
{
  sm3_update (hmac_sm3_256_ctx, data, data_size);
  return TRUE;
}

/**
  Completes computation of the HMAC-SM3_256 digest value.

  This function completes HMAC-SM3_256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SM3_256 context cannot
  be used again.
  HMAC-SM3_256 context should be initialized by hmac_sm3_256_new(), and should not be finalized
  by hmac_sm3_256_final(). Behavior with invalid HMAC-SM3_256 context is undefined.

  If hmac_sm3_256_ctx is NULL, then return FALSE.
  If hmac_value is NULL, then return FALSE.

  @param[in, out]  hmac_sm3_256_ctx  Pointer to the HMAC-SM3_256 context.
  @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SM3_256 digest
                                      value (32 bytes).

  @retval TRUE   HMAC-SM3_256 digest computation succeeded.
  @retval FALSE  HMAC-SM3_256 digest computation failed.

**/
boolean hmac_sm3_256_final(IN OUT void *hmac_sm3_256_ctx, OUT uint8 *hmac_value)
{
  sm3_256_final (hmac_sm3_256_ctx, hmac_value);
  return TRUE;
}

/**
  Computes the HMAC-SM3_256 digest of a input data buffer.

  This function performs the HMAC-SM3_256 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   data        Pointer to the buffer containing the data to be digested.
  @param[in]   data_size    size of data buffer in bytes.
  @param[in]   key         Pointer to the user-supplied key.
  @param[in]   key_size     key size in bytes.
  @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SM3_256 digest
                           value (32 bytes).

  @retval TRUE   HMAC-SM3_256 digest computation succeeded.
  @retval FALSE  HMAC-SM3_256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
boolean hmac_sm3_256_all(IN const void *data, IN uintn data_size,
			IN const uint8 *key, IN uintn key_size,
			OUT uint8 *hmac_value)
{
  sm3_hmac (key, key_size, data, data_size, hmac_value);
  return TRUE;
}
