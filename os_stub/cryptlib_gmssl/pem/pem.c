/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
**/

#include "internal_crypt_lib.h"

static uintn ascii_str_len(IN const char8 *string)
{
	uintn length;

	ASSERT(string != NULL);
	if (string == NULL) {
		return 0;
	}

	for (length = 0; *string != '\0'; string++, length++) {
		;
	}
	return length;
}

/**
  Callback function for password phrase conversion used for retrieving the encrypted PEM.

  @param[out]  buf      Pointer to the buffer to write the passphrase to.
  @param[in]   size     Maximum length of the passphrase (i.e. the size of buf).
  @param[in]   flag     A flag which is set to 0 when reading and 1 when writing.
  @param[in]   key      key data to be passed to the callback routine.

  @retval  The number of characters in the passphrase or 0 if an error occurred.

**/
intn PasswordCallback(OUT char8 *buf, IN intn size, IN intn flag, IN void *key)
{
	intn key_length;

	zero_mem((void *)buf, (uintn)size);
	if (key != NULL) {
		//
		// Duplicate key phrase directly.
		//
		key_length = (intn)ascii_str_len((char8 *)key);
		key_length = (key_length > size) ? size : key_length;
		copy_mem(buf, key, (uintn)key_length);
		return key_length;
	} else {
		return 0;
	}
}

/**
  Retrieve the RSA Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
                           RSA private key component. Use rsa_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If rsa_context is NULL, then return FALSE.

  @retval  TRUE   RSA Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean rsa_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **rsa_context)
{
	return FALSE;
}

/**
  Retrieve the EC Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
                           EC private key component. Use ec_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If ec_context is NULL, then return FALSE.

  @retval  TRUE   EC Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean ec_get_private_key_from_pem(IN const uint8 *pem_data, IN uintn pem_size,
				    IN const char8 *password,
				    OUT void **ec_context)
{
	return FALSE;
}

/**
  Retrieve the Ed Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
                           Ed private key component. Use ecd_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If ecd_context is NULL, then return FALSE.

  @retval  TRUE   Ed Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean ecd_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **ecd_context)
{
	return FALSE;
}

/**
  Retrieve the sm2 Private key from the password-protected PEM key data.

  @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  pem_size      size of the PEM key data in bytes.
  @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
                           sm2 private key component. Use sm2_free() function to free the
                           resource.

  If pem_data is NULL, then return FALSE.
  If sm2_context is NULL, then return FALSE.

  @retval  TRUE   sm2 Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.

**/
boolean sm2_get_private_key_from_pem(IN const uint8 *pem_data,
				     IN uintn pem_size,
				     IN const char8 *password,
				     OUT void **sm2_context)
{
	return FALSE;
}
