/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  AEAD (SM4-GCM) Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <gmssl/sm4.h>

/**
  Performs AEAD SM4-GCM authenticated encryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 16, otherwise FALSE is returned.
  tag_size must be 16, otherwise FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be encrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the encryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD SM4-GCM authenticated encryption succeeded.
  @retval FALSE  AEAD SM4-GCM authenticated encryption failed.

**/
boolean aead_sm4_gcm_encrypt(IN const uint8 *key, IN uintn key_size,
			     IN const uint8 *iv, IN uintn iv_size,
			     IN const uint8 *a_data, IN uintn a_data_size,
			     IN const uint8 *data_in, IN uintn data_in_size,
			     OUT uint8 *tag_out, IN uintn tag_size,
			     OUT uint8 *data_out, OUT uintn *data_out_size)
{
  SM4_KEY  sm4_key;
  int      result;

  sm4_set_encrypt_key(&sm4_key, key);

  result = sm4_gcm_encrypt (&sm4_key, iv, iv_size,
    a_data, a_data_size, data_in, data_in_size,
    data_out, tag_size, tag_out);
  if (result != 1) {
    return FALSE;
  }

  *data_out_size = data_in_size;

	return TRUE;
}

/**
  Performs AEAD SM4-GCM authenticated decryption on a data buffer and additional authenticated data (AAD).

  iv_size must be 12, otherwise FALSE is returned.
  key_size must be 16, otherwise FALSE is returned.
  tag_size must be 16, otherwise FALSE is returned.
  If additional authenticated data verification fails, FALSE is returned.

  @param[in]   key         Pointer to the encryption key.
  @param[in]   key_size     size of the encryption key in bytes.
  @param[in]   iv          Pointer to the IV value.
  @param[in]   iv_size      size of the IV value in bytes.
  @param[in]   a_data       Pointer to the additional authenticated data (AAD).
  @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
  @param[in]   data_in      Pointer to the input data buffer to be decrypted.
  @param[in]   data_in_size  size of the input data buffer in bytes.
  @param[in]   tag         Pointer to a buffer that contains the authentication tag.
  @param[in]   tag_size     size of the authentication tag in bytes.
  @param[out]  data_out     Pointer to a buffer that receives the decryption output.
  @param[out]  data_out_size size of the output data buffer in bytes.

  @retval TRUE   AEAD SM4-GCM authenticated decryption succeeded.
  @retval FALSE  AEAD SM4-GCM authenticated decryption failed.

**/
boolean aead_sm4_gcm_decrypt(IN const uint8 *key, IN uintn key_size,
			     IN const uint8 *iv, IN uintn iv_size,
			     IN const uint8 *a_data, IN uintn a_data_size,
			     IN const uint8 *data_in, IN uintn data_in_size,
			     IN const uint8 *tag, IN uintn tag_size,
			     OUT uint8 *data_out, OUT uintn *data_out_size)
{
  SM4_KEY  sm4_key;
  int      result;

  sm4_set_decrypt_key(&sm4_key, key);

  result = sm4_gcm_decrypt (&sm4_key, iv, iv_size,
    a_data, a_data_size, data_in, data_in_size,
    tag, tag_size, data_out);
  if (result != 1) {
    return FALSE;
  }

  *data_out_size = data_in_size;

	return TRUE;
}
