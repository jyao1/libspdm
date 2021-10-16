/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  HMAC-SM3_256 KDF Wrapper Implementation.

  RFC 5869: HMAC-based Extract-and-Expand key Derivation Function (HKDF)
**/

#include "internal_crypt_lib.h"
#include <gmssl/hkdf.h>

/**
  Derive SM3_256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sm3_256_extract_and_expand(IN const uint8 *key, IN uintn key_size,
				       IN const uint8 *salt, IN uintn salt_size,
				       IN const uint8 *info, IN uintn info_size,
				       OUT uint8 *out, IN uintn out_size)
{
  int result;
  uint8 prk[32];
  uintn prk_size;

  prk_size = sizeof(prk);
  result = hkdf_extract (DIGEST_sm3(), salt, salt_size, key, key_size, prk, &prk_size);
  if (result != 1) {
    return FALSE;
  }
  result = hkdf_expand (DIGEST_sm3(), prk, prk_size, info, info_size, out_size, out);
  if (result != 1) {
    return FALSE;
  }
	return TRUE;
}

/**
  Derive SM3_256 HMAC-based Extract key Derivation Function (HKDF).

  @param[in]   key              Pointer to the user-supplied key.
  @param[in]   key_size          key size in bytes.
  @param[in]   salt             Pointer to the salt(non-secret) value.
  @param[in]   salt_size         salt size in bytes.
  @param[out]  prk_out           Pointer to buffer to receive hkdf value.
  @param[in]   prk_out_size       size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sm3_256_extract(IN const uint8 *key, IN uintn key_size,
			    IN const uint8 *salt, IN uintn salt_size,
			    OUT uint8 *prk_out, IN uintn prk_out_size)
{
  int result;
  result = hkdf_extract (DIGEST_sm3(), salt, salt_size, key, key_size, prk_out, &prk_out_size);
  if (result != 1) {
    return FALSE;
  }
	return TRUE;
}

/**
  Derive SM3_256 HMAC-based Expand key Derivation Function (HKDF).

  @param[in]   prk              Pointer to the user-supplied key.
  @param[in]   prk_size          key size in bytes.
  @param[in]   info             Pointer to the application specific info.
  @param[in]   info_size         info size in bytes.
  @param[out]  out              Pointer to buffer to receive hkdf value.
  @param[in]   out_size          size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.

**/
boolean hkdf_sm3_256_expand(IN const uint8 *prk, IN uintn prk_size,
			   IN const uint8 *info, IN uintn info_size,
			   OUT uint8 *out, IN uintn out_size)
{
  int result;
  result = hkdf_expand (DIGEST_sm3(), prk, prk_size, info, info_size, out_size, out);
  if (result != 1) {
    return FALSE;
  }
	return TRUE;
}
