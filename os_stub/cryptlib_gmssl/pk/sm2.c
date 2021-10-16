/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Shang-Mi2 Asymmetric Wrapper Implementation.
**/

#include "internal_crypt_lib.h"
#include <gmssl/sm2.h>

/**
  Allocates and Initializes one Shang-Mi2 context for subsequent use.

  The key is generated before the function returns.

  @return  Pointer to the Shang-Mi2 context that has been initialized.
           If the allocations fails, sm2_new() returns NULL.

**/
void *sm2_new(void)
{
	SM2_KEY  *sm2_key;

	sm2_key = allocate_pool (sizeof(SM2_KEY));
	return sm2_key;
}

/**
  Release the specified sm2 context.

  @param[in]  sm2_context  Pointer to the sm2 context to be released.

**/
void sm2_free(IN void *sm2_context)
{
	zero_mem (sm2_context, sizeof(SM2_KEY));
	free_pool (sm2_context);
}

/**
  Sets the public key component into the established sm2 context.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  @param[in, out]  ec_context      Pointer to sm2 context being set.
  @param[in]       public         Pointer to the buffer to receive generated public X,Y.
  @param[in]       public_size     The size of public buffer in bytes.

  @retval  TRUE   sm2 public key component was set successfully.
  @retval  FALSE  Invalid sm2 public key component.

**/
boolean sm2_set_pub_key(IN OUT void *sm2_context, IN uint8 *public_key,
			IN uintn public_key_size)
{
	int result;
	if (public_key_size != 64) {
		return FALSE;
	}
	result = sm2_set_public_key (sm2_context, public_key);
	if (result != 1) {
		return FALSE;
	}
	return TRUE;
}

/**
  Gets the public key component from the established sm2 context.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  @param[in, out]  sm2_context     Pointer to sm2 context being set.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval  TRUE   sm2 key component was retrieved successfully.
  @retval  FALSE  Invalid sm2 key component.

**/
boolean sm2_get_pub_key(IN OUT void *sm2_context, OUT uint8 *public_key,
			IN OUT uintn *public_key_size)
{
	SM2_KEY *key;

	if (*public_key_size < 64) {
		*public_key_size = 64;
		return FALSE;
	}
	*public_key_size = 64;
	key = sm2_context;
	copy_mem (public_key, &key->public_key, 64);
	return TRUE;
}

/**
  Validates key components of sm2 context.
  NOTE: This function performs integrity checks on all the sm2 key material, so
        the sm2 key structure must contain all the private key data.

  If sm2_context is NULL, then return FALSE.

  @param[in]  sm2_context  Pointer to sm2 context to check.

  @retval  TRUE   sm2 key components are valid.
  @retval  FALSE  sm2 key components are not valid.

**/
boolean sm2_check_key(IN void *sm2_context)
{
	return TRUE;
}

/**
  Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.

  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter public, public_size.
  X is the first half of public with size being public_size / 2,
  Y is the second half of public with size being public_size / 2.
  sm2 context is updated accordingly.
  If the public buffer is too small to hold the public X, Y, FALSE is returned and
  public_size is set to the required buffer size to obtain the public X, Y.

  The public_size is 64. first 32-byte is X, second 32-byte is Y.

  If sm2_context is NULL, then return FALSE.
  If public_size is NULL, then return FALSE.
  If public_size is large enough but public is NULL, then return FALSE.

  @param[in, out]  sm2_context     Pointer to the sm2 context.
  @param[out]      public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  public_size     On input, the size of public buffer in bytes.
                                  On output, the size of data returned in public buffer in bytes.

  @retval TRUE   sm2 public X,Y generation succeeded.
  @retval FALSE  sm2 public X,Y generation failed.
  @retval FALSE  public_size is not large enough.

**/
boolean sm2_generate_key(IN OUT void *sm2_context, OUT uint8 *public,
			 IN OUT uintn *public_size)
{
	int result;
	SM2_KEY *key;

	if (*public_size < 64) {
		*public_size = 64;
		return FALSE;
	}

	result = sm2_keygen (sm2_context);
	if (result != 1) {
		return FALSE;
	}

	*public_size = 64;
	key = sm2_context;
	copy_mem (public, &key->public_key, 64);
	return TRUE;
}

/**
  Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.

  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of peer_public with size being peer_public_size / 2,
  Y is the second half of peer_public with size being peer_public_size / 2.

  If sm2_context is NULL, then return FALSE.
  If peer_public is NULL, then return FALSE.
  If peer_public_size is 0, then return FALSE.
  If key is NULL, then return FALSE.

  The id_a_size and id_b_size must be smaller than 2^16-1.
  The peer_public_size is 64. first 32-byte is X, second 32-byte is Y.
  The key_size must be smaller than 2^32-1, limited by KDF function.

  @param[in, out]  sm2_context         Pointer to the sm2 context.
  @param[in]       hash_nid            hash NID
  @param[in]       id_a                the ID-A of the key exchange context.
  @param[in]       id_a_size           size of ID-A key exchange context.
  @param[in]       id_b                the ID-B of the key exchange context.
  @param[in]       id_b_size           size of ID-B key exchange context.
  @param[in]       peer_public         Pointer to the peer's public X,Y.
  @param[in]       peer_public_size     size of peer's public X,Y in bytes.
  @param[out]      key                Pointer to the buffer to receive generated key.
  @param[in]       key_size            On input, the size of key buffer in bytes.

  @retval TRUE   sm2 exchanged key generation succeeded.
  @retval FALSE  sm2 exchanged key generation failed.

**/
boolean sm2_compute_key(IN OUT void *sm2_context, IN uintn hash_nid,
			IN const uint8 *id_a, IN uintn id_a_size,
			IN const uint8 *id_b, IN uintn id_b_size,
			IN const uint8 *peer_public,
			IN uintn peer_public_size, OUT uint8 *key,
			IN uintn key_size)
{
	// TBD
	return FALSE;
}

static void ecc_signature_der_to_bin(IN uint8 *der_signature,
				     IN uintn der_sig_size,
				     OUT uint8 *signature, IN uintn sig_size)
{
	uint8 der_r_size;
	uint8 der_s_size;
	uint8 *bn_r;
	uint8 *bn_s;
	uint8 r_size;
	uint8 s_size;
	uint8 half_size;

	half_size = (uint8)(sig_size / 2);

	ASSERT(der_signature[0] == 0x30);
	ASSERT((uintn)(der_signature[1] + 2) == der_sig_size);
	ASSERT(der_signature[2] == 0x02);
	der_r_size = der_signature[3];
	ASSERT(der_signature[4 + der_r_size] == 0x02);
	der_s_size = der_signature[5 + der_r_size];
	ASSERT(der_sig_size == (uintn)(der_r_size + der_s_size + 6));

	if (der_signature[4] != 0) {
		r_size = der_r_size;
		bn_r = &der_signature[4];
	} else {
		r_size = der_r_size - 1;
		bn_r = &der_signature[5];
	}
	if (der_signature[6 + der_r_size] != 0) {
		s_size = der_s_size;
		bn_s = &der_signature[6 + der_r_size];
	} else {
		s_size = der_s_size - 1;
		bn_s = &der_signature[7 + der_r_size];
	}
	ASSERT(r_size <= half_size && s_size <= half_size);
	zero_mem(signature, sig_size);
	copy_mem(&signature[0 + half_size - r_size], bn_r, r_size);
	copy_mem(&signature[half_size + half_size - s_size], bn_s, s_size);
}

static void ecc_signature_bin_to_der(IN uint8 *signature, IN uintn sig_size,
				     OUT uint8 *der_signature,
				     IN OUT uintn *der_sig_size_in_out)
{
	uintn der_sig_size;
	uint8 der_r_size;
	uint8 der_s_size;
	uint8 *bn_r;
	uint8 *bn_s;
	uint8 r_size;
	uint8 s_size;
	uint8 half_size;
	uint8 index;

	half_size = (uint8)(sig_size / 2);

	for (index = 0; index < half_size; index++) {
		if (signature[index] != 0) {
			break;
		}
	}
	r_size = (uint8)(half_size - index);
	bn_r = &signature[index];
	for (index = 0; index < half_size; index++) {
		if (signature[half_size + index] != 0) {
			break;
		}
	}
	s_size = (uint8)(half_size - index);
	bn_s = &signature[half_size + index];
	if (r_size == 0 || s_size == 0) {
		*der_sig_size_in_out = 0;
		return;
	}
	if (bn_r[0] < 0x80) {
		der_r_size = r_size;
	} else {
		der_r_size = r_size + 1;
	}
	if (bn_s[0] < 0x80) {
		der_s_size = s_size;
	} else {
		der_s_size = s_size + 1;
	}
	der_sig_size = der_r_size + der_s_size + 6;
	ASSERT(der_sig_size <= *der_sig_size_in_out);
	*der_sig_size_in_out = der_sig_size;
	zero_mem(der_signature, der_sig_size);
	der_signature[0] = 0x30;
	der_signature[1] = (uint8)(der_sig_size - 2);
	der_signature[2] = 0x02;
	der_signature[3] = der_r_size;
	if (bn_r[0] < 0x80) {
		copy_mem(&der_signature[4], bn_r, r_size);
	} else {
		copy_mem(&der_signature[5], bn_r, r_size);
	}
	der_signature[4 + der_r_size] = 0x02;
	der_signature[5 + der_r_size] = der_s_size;
	if (bn_s[0] < 0x80) {
		copy_mem(&der_signature[6 + der_r_size], bn_s, s_size);
	} else {
		copy_mem(&der_signature[7 + der_r_size], bn_s, s_size);
	}
}

/**
  Carries out the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.

  This function carries out the SM2 signature.
  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  If sm2_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  hash_nid must be SM3_256.
  If sig_size is large enough but signature is NULL, then return FALSE.

  The id_a_size must be smaller than 2^16-1.
  The sig_size is 64. first 32-byte is R, second 32-byte is S.

  @param[in]       sm2_context   Pointer to sm2 context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       id_a          the ID-A of the signing context.
  @param[in]       id_a_size     size of ID-A signing context.
  @param[in]       message      Pointer to octet message to be signed (before hash).
  @param[in]       size         size of the message in bytes.
  @param[out]      signature    Pointer to buffer to receive SM2 signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated in SM2.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean sm2_dsa_sign(IN void *sm2_context, IN uintn hash_nid,
		       IN const uint8 *id_a, IN uintn id_a_size,
		       IN const uint8 *message, IN uintn size,
		       OUT uint8 *signature, IN OUT uintn *sig_size)
{
	SM2_SIGN_CTX  sm2_sign_ctx;
	uint8 *id;
	int result;
	uint8 der_signature[32 * 2 + 8];
	uintn der_sig_size;

	if (hash_nid != CRYPTO_NID_SM3_256) {
		return FALSE;
	}
	if (*sig_size < 64) {
		*sig_size = 64;
		return FALSE;
	}
	*sig_size = 64;

	id = allocate_pool (id_a_size + 1);
	if (id == NULL) {
		return FALSE;
	}
	copy_mem (id, id_a, id_a_size);
	id[id_a_size] = 0;

	result = sm2_sign_init (&sm2_sign_ctx, sm2_context, id);
	if (result != 1) {
		return FALSE;
	}
	free_pool (id);

    result = sm2_sign_update(&sm2_sign_ctx, message, size);
	if (result != 1) {
		zero_mem (&sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
		return FALSE;
	}

	der_sig_size = sizeof(der_signature);
	result = sm2_sign_finish(&sm2_sign_ctx, der_signature, &der_sig_size);
	if (result != 1) {
		zero_mem (&sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
		return FALSE;
	}
	zero_mem (&sm2_sign_ctx, sizeof(SM2_SIGN_CTX));

	ecc_signature_der_to_bin(der_signature, der_sig_size, signature, *sig_size);

	return TRUE;
}

/**
  Verifies the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.

  If sm2_context is NULL, then return FALSE.
  If message is NULL, then return FALSE.
  If signature is NULL, then return FALSE.
  hash_nid must be SM3_256.

  The id_a_size must be smaller than 2^16-1.
  The sig_size is 64. first 32-byte is R, second 32-byte is S.

  @param[in]  sm2_context   Pointer to SM2 context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  id_a          the ID-A of the signing context.
  @param[in]  id_a_size     size of ID-A signing context.
  @param[in]  message      Pointer to octet message to be checked (before hash).
  @param[in]  size         size of the message in bytes.
  @param[in]  signature    Pointer to SM2 signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded in SM2.
  @retval  FALSE  Invalid signature or invalid sm2 context.

**/
boolean sm2_dsa_verify(IN void *sm2_context, IN uintn hash_nid,
			 IN const uint8 *id_a, IN uintn id_a_size,
			 IN const uint8 *message, IN uintn size,
			 IN const uint8 *signature, IN uintn sig_size)
{
	SM2_SIGN_CTX  sm2_sign_ctx;
	uint8 *id;
	int result;
	uint8 der_signature[32 * 2 + 8];
	uintn der_sig_size;

	if (hash_nid != CRYPTO_NID_SM3_256) {
		return FALSE;
	}
	if (sig_size != 64) {
		return FALSE;
	}

	der_sig_size = sizeof(der_signature);
	ecc_signature_bin_to_der((uint8 *)signature, sig_size, der_signature, &der_sig_size);

	id = allocate_pool (id_a_size + 1);
	if (id == NULL) {
		return FALSE;
	}
	copy_mem (id, id_a, id_a_size);
	id[id_a_size] = 0;

	result = sm2_verify_init (&sm2_sign_ctx, sm2_context, id);
	if (result != 1) {
		return FALSE;
	}
	free_pool (id);

    result = sm2_verify_update(&sm2_sign_ctx, message, size);
	if (result != 1) {
		zero_mem (&sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
		return FALSE;
	}

	der_sig_size = sizeof(der_signature);
	result = sm2_verify_finish(&sm2_sign_ctx, der_signature, der_sig_size);
	if (result != 1) {
		zero_mem (&sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
		return FALSE;
	}
	zero_mem (&sm2_sign_ctx, sizeof(SM2_SIGN_CTX));

	return TRUE;
}
