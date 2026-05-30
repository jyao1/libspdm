/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Elliptic Curve Wrapper Implementation for AWS-LC.
 *
 * NOTE: Adapted from the OpenSSL wrapper. AWS-LC maintains API compatibility
 * for EC operations (EC_KEY, EC_POINT, EVP_PKEY, ECDSA_SIG).
 * Key differences from OpenSSL 3.x:
 * - No EVP_MD_fetch/EVP_MD_free (use EVP_sha256() etc. directly)
 * - No OSSL_PARAM / param_build for key import (use EC_KEY APIs)
 * - No EVP_PKEY_CTX_new_from_name (use EVP_PKEY_CTX_new_id or EC_KEY)
 *
 * RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
 * FIPS 186-4 - Digital Signature Standard (DSS)
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <string.h>

#define MAX_CURVE_BYTES 66 /* P-521 */
#define MAX_KEY_SIZE (66 * 2 + 1) /* One extra byte for uncompressed format */
#define MAX_DER_SIGN_SIZE ((MAX_CURVE_BYTES + 3) * 2 + 6)

/**
 * Helper: map SPDM NID to OpenSSL NID.
 */
static int libspdm_ec_get_openssl_nid(size_t nid)
{
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_SECP256R1:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256:
        return NID_X9_62_prime256v1;
    case LIBSPDM_CRYPTO_NID_SECP384R1:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384:
        return NID_secp384r1;
    case LIBSPDM_CRYPTO_NID_SECP521R1:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521:
        return NID_secp521r1;
    default:
        return NID_undef;
    }
}

/**
 * Helper: get half size from EVP_PKEY bits.
 */
static int evp_pkey_get_half_size(EVP_PKEY *evp_pkey)
{
    switch (EVP_PKEY_bits(evp_pkey)) {
    case 256:
        return 32;
    case 384:
        return 48;
    case 521:
        return 66;
    default:
        return -1;
    }
}

/**
 * Allocates and Initializes one Elliptic Curve context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Elliptic Curve context that has been initialized.
 *         If the allocations fails, libspdm_ec_new_by_nid() returns NULL.
 **/
void *libspdm_ec_new_by_nid(size_t nid)
{
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    libspdm_key_context *ec_ctx = NULL;
    int openssl_nid;

    openssl_nid = libspdm_ec_get_openssl_nid(nid);
    if (openssl_nid == NID_undef) {
        return NULL;
    }

    ec_key = EC_KEY_new_by_curve_name(openssl_nid);
    if (ec_key == NULL) {
        return NULL;
    }

    if (EC_KEY_generate_key(ec_key) != 1) {
        EC_KEY_free(ec_key);
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EC_KEY_free(ec_key);
        return NULL;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        return NULL;
    }
    /* ec_key ownership transferred to pkey */

    ec_ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ec_ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ec_ctx->evp_pkey = pkey;

    return ec_ctx;
}

/**
 * Release the specified EC context.
 *
 * @param[in]  ec_context  Pointer to the EC context to be released.
 **/
void libspdm_ec_free(void *ec_context)
{
    if (ec_context == NULL) {
        return;
    }
    libspdm_key_context *ec_ctx = (libspdm_key_context *)ec_context;
    if (ec_ctx->evp_pkey != NULL) {
        EVP_PKEY_free(ec_ctx->evp_pkey);
    }
    free(ec_ctx);
}

/**
 * Sets the public key component into the established EC context.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to EC context being set.
 * @param[in]       public_key      Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_key_size The size of public buffer in bytes.
 *
 * @retval  true   EC public key component was set successfully.
 * @retval  false  Invalid EC public key component.
 **/
bool libspdm_ec_set_pub_key(void *ec_context, const uint8_t *public_key,
                            size_t public_key_size)
{
    libspdm_key_context *ec_ctx;
    EVP_PKEY *evp_pkey;
    EC_KEY *ec_key;
    const EC_GROUP *group;
    EC_POINT *point = NULL;
    uint8_t oct_key[MAX_KEY_SIZE];
    size_t oct_len;
    int half_size;
    bool result = false;

    if (ec_context == NULL || public_key == NULL) {
        return false;
    }

    ec_ctx = (libspdm_key_context *)ec_context;
    evp_pkey = ec_ctx->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    ec_key = (EC_KEY *)EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size < 0) {
        return false;
    }

    /* Build uncompressed octet: 0x04 || X || Y */
    if ((size_t)half_size * 2 == public_key_size) {
        oct_key[0] = 0x04;
        memcpy(oct_key + 1, public_key, public_key_size);
        oct_len = 1 + public_key_size;
    } else if (public_key_size == (size_t)half_size * 2 + 1 && public_key[0] == 0x04) {
        memcpy(oct_key, public_key, public_key_size);
        oct_len = public_key_size;
    } else {
        return false;
    }

    point = EC_POINT_new(group);
    if (point == NULL) {
        return false;
    }

    if (EC_POINT_oct2point(group, point, oct_key, oct_len, NULL) != 1) {
        goto cleanup;
    }

    /* Create a new EC_KEY with just the public key on the same curve */
    {
        EC_KEY *new_ec_key;
        EVP_PKEY *new_pkey;
        int curve_nid;

        curve_nid = EC_GROUP_get_curve_name(group);
        new_ec_key = EC_KEY_new_by_curve_name(curve_nid);
        if (new_ec_key == NULL) {
            goto cleanup;
        }

        if (EC_KEY_set_public_key(new_ec_key, point) != 1) {
            EC_KEY_free(new_ec_key);
            goto cleanup;
        }

        if (EC_KEY_check_key(new_ec_key) != 1) {
            EC_KEY_free(new_ec_key);
            goto cleanup;
        }

        new_pkey = EVP_PKEY_new();
        if (new_pkey == NULL) {
            EC_KEY_free(new_ec_key);
            goto cleanup;
        }

        if (EVP_PKEY_assign_EC_KEY(new_pkey, new_ec_key) != 1) {
            EVP_PKEY_free(new_pkey);
            EC_KEY_free(new_ec_key);
            goto cleanup;
        }

        EVP_PKEY_free(ec_ctx->evp_pkey);
        ec_ctx->evp_pkey = new_pkey;
        result = true;
    }

cleanup:
    EC_POINT_free(point);
    return result;
}

/**
 * Sets the private key component into the established EC context.
 *
 * @param[in, out]  ec_context       Pointer to EC context being set.
 * @param[in]       private_key      Pointer to the private key buffer.
 * @param[in]       private_key_size The size of private key buffer in bytes.
 *
 * @retval  true   EC private key component was set successfully.
 * @retval  false  Invalid EC private key component.
 **/
bool libspdm_ec_set_priv_key(void *ec_context, const uint8_t *private_key,
                             size_t private_key_size)
{
    libspdm_key_context *ec_ctx;
    EVP_PKEY *evp_pkey;
    EC_KEY *ec_key;
    const EC_GROUP *group;
    BIGNUM *priv_bn = NULL;
    EC_KEY *new_ec_key = NULL;
    EVP_PKEY *new_pkey = NULL;
    EC_POINT *pub_point = NULL;
    int half_size;
    int curve_nid;
    bool result = false;

    if (ec_context == NULL || private_key == NULL) {
        return false;
    }

    ec_ctx = (libspdm_key_context *)ec_context;
    evp_pkey = ec_ctx->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    ec_key = (EC_KEY *)EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size < 0 || private_key_size != (size_t)half_size) {
        return false;
    }

    priv_bn = BN_bin2bn(private_key, (int)private_key_size, NULL);
    if (priv_bn == NULL) {
        return false;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    new_ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (new_ec_key == NULL) {
        BN_free(priv_bn);
        return false;
    }

    if (EC_KEY_set_private_key(new_ec_key, priv_bn) != 1) {
        goto cleanup;
    }

    /* Compute public key from private key */
    pub_point = EC_POINT_new(EC_KEY_get0_group(new_ec_key));
    if (pub_point == NULL) {
        goto cleanup;
    }

    if (EC_POINT_mul(EC_KEY_get0_group(new_ec_key), pub_point, priv_bn, NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EC_KEY_set_public_key(new_ec_key, pub_point) != 1) {
        goto cleanup;
    }

    if (EC_KEY_check_key(new_ec_key) != 1) {
        goto cleanup;
    }

    new_pkey = EVP_PKEY_new();
    if (new_pkey == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_assign_EC_KEY(new_pkey, new_ec_key) != 1) {
        EVP_PKEY_free(new_pkey);
        new_pkey = NULL;
        goto cleanup;
    }
    /* new_ec_key ownership transferred */
    new_ec_key = NULL;

    EVP_PKEY_free(ec_ctx->evp_pkey);
    ec_ctx->evp_pkey = new_pkey;
    new_pkey = NULL;
    result = true;

cleanup:
    BN_free(priv_bn);
    EC_KEY_free(new_ec_key);
    EVP_PKEY_free(new_pkey);
    EC_POINT_free(pub_point);
    return result;
}

/**
 * Gets the public key component from the established EC context.
 *
 * For P-256, the public_size is 64. first 32-byte is X, second 32-byte is Y.
 * For P-384, the public_size is 96. first 48-byte is X, second 48-byte is Y.
 * For P-521, the public_size is 132. first 66-byte is X, second 66-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to EC context being set.
 * @param[out]      public_key      Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_key_size On input, the size of public buffer in bytes.
 *                                  On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   EC key component was retrieved successfully.
 * @retval  false  Invalid EC key component.
 **/
bool libspdm_ec_get_pub_key(void *ec_context, uint8_t *public_key,
                            size_t *public_key_size)
{
    EVP_PKEY *evp_pkey;
    const EC_KEY *ec_key;
    const EC_POINT *point;
    const EC_GROUP *group;
    uint8_t buffer[MAX_KEY_SIZE];
    size_t len;
    int half_size;

    if (ec_context == NULL || public_key == NULL ||
        public_key_size == NULL) {
        return false;
    }

    evp_pkey = ((libspdm_key_context *)ec_context)->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    point = EC_KEY_get0_public_key(ec_key);
    group = EC_KEY_get0_group(ec_key);
    if (point == NULL || group == NULL) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size < 0) {
        return false;
    }

    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                            buffer, sizeof(buffer), NULL);
    if (len == 0) {
        return false;
    }

    /* len includes 0x04 prefix */
    if (*public_key_size < len - 1) {
        *public_key_size = len - 1;
        return false;
    }

    *public_key_size = len - 1;
    /* Skip 0x04 prefix */
    memcpy(public_key, buffer + 1, *public_key_size);

    return true;
}

/**
 * Validates key components of EC context.
 *
 * @param[in]  ec_context  Pointer to EC context to check.
 *
 * @retval  true   EC key components are valid.
 * @retval  false  EC key components are not valid.
 **/
bool libspdm_ec_check_key(const void *ec_context)
{
    EVP_PKEY *evp_pkey;
    const EC_KEY *ec_key;

    if (ec_context == NULL) {
        return false;
    }

    evp_pkey = ((libspdm_key_context *)ec_context)->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    return (EC_KEY_check_key(ec_key) == 1);
}

/**
 * Generates EC key and returns EC public key (X, Y).
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * The key is already generated at new time. This just retrieves the public key.
 *
 * @param[in, out]  ec_context      Pointer to the EC context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                  On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   EC public X,Y generation succeeded.
 * @retval false  EC public X,Y generation failed.
 * @retval false  public_size is not large enough.
 **/
bool libspdm_ec_generate_key(void *ec_context, uint8_t *public_data,
                             size_t *public_size)
{
    return libspdm_ec_get_pub_key(ec_context, public_data, public_size);
}

/**
 * Computes exchanged common key.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 *
 * @param[in, out]  ec_context          Pointer to the EC context.
 * @param[in]       peer_public         Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size    size of peer's public X,Y in bytes.
 * @param[out]      key                 Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                      On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   EC exchanged key generation succeeded.
 * @retval false  EC exchanged key generation failed.
 * @retval false  key_size is not large enough.
 **/
bool libspdm_ec_compute_key(void *ec_context, const uint8_t *peer_public,
                            size_t peer_public_size, uint8_t *key,
                            size_t *key_size)
{
    EVP_PKEY *evp_pkey;
    EVP_PKEY *peer_pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EC_KEY *peer_ec_key = NULL;
    const EC_KEY *ec_key;
    const EC_GROUP *group;
    EC_POINT *peer_point = NULL;
    uint8_t oct_key[MAX_KEY_SIZE];
    size_t oct_len;
    int half_size;
    int curve_nid;
    bool result = false;

    if (ec_context == NULL || peer_public == NULL || key == NULL || key_size == NULL) {
        return false;
    }

    evp_pkey = ((libspdm_key_context *)ec_context)->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size < 0) {
        return false;
    }

    /* Build uncompressed peer public key */
    if ((size_t)half_size * 2 == peer_public_size) {
        oct_key[0] = 0x04;
        memcpy(oct_key + 1, peer_public, peer_public_size);
        oct_len = 1 + peer_public_size;
    } else {
        memcpy(oct_key, peer_public, peer_public_size);
        oct_len = peer_public_size;
    }

    /* Create peer EC key */
    curve_nid = EC_GROUP_get_curve_name(group);
    peer_ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (peer_ec_key == NULL) {
        return false;
    }

    peer_point = EC_POINT_new(EC_KEY_get0_group(peer_ec_key));
    if (peer_point == NULL) {
        goto cleanup;
    }

    if (EC_POINT_oct2point(EC_KEY_get0_group(peer_ec_key), peer_point,
                           oct_key, oct_len, NULL) != 1) {
        goto cleanup;
    }

    if (EC_KEY_set_public_key(peer_ec_key, peer_point) != 1) {
        goto cleanup;
    }

    peer_pkey = EVP_PKEY_new();
    if (peer_pkey == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_assign_EC_KEY(peer_pkey, peer_ec_key) != 1) {
        goto cleanup;
    }
    peer_ec_key = NULL; /* ownership transferred */

    /* Perform ECDH */
    ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_derive(ctx, key, key_size) <= 0) {
        goto cleanup;
    }

    result = true;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EC_KEY_free(peer_ec_key);
    EC_POINT_free(peer_point);
    return result;
}

/**
 * Carries out the EC-DSA signature.
 *
 * This function carries out the EC-DSA signature.
 * The signature is in raw R||S format.
 *
 * @param[in]       ec_context    Pointer to EC context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature     Pointer to buffer to receive EC-DSA signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                                On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in EC-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 **/
bool libspdm_ecdsa_sign(void *ec_context, size_t hash_nid,
                        const uint8_t *message_hash, size_t hash_size,
                        uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY *evp_pkey;
    const EC_KEY *ec_key;
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *bn_r;
    const BIGNUM *bn_s;
    int half_size;
    int r_size, s_size;

    if (ec_context == NULL || message_hash == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    evp_pkey = ((libspdm_key_context *)ec_context)->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size < 0) {
        return false;
    }

    if (*sig_size < (size_t)(half_size * 2)) {
        *sig_size = half_size * 2;
        return false;
    }
    *sig_size = half_size * 2;
    libspdm_zero_mem(signature, *sig_size);

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;
    default:
        return false;
    }

    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    ecdsa_sig = ECDSA_do_sign(message_hash, (int)hash_size, (EC_KEY *)ec_key);
    if (ecdsa_sig == NULL) {
        return false;
    }

    ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);

    r_size = BN_num_bytes(bn_r);
    s_size = BN_num_bytes(bn_s);
    if (r_size <= 0 || s_size <= 0) {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }
    if (r_size > half_size || s_size > half_size) {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    BN_bn2bin(bn_r, &signature[half_size - r_size]);
    BN_bn2bin(bn_s, &signature[half_size + half_size - s_size]);

    ECDSA_SIG_free(ecdsa_sig);
    return true;
}

/**
 * Verifies the EC-DSA signature.
 *
 * @param[in]  ec_context    Pointer to EC context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature     Pointer to EC-DSA signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in EC-DSA.
 * @retval  false  Invalid signature or invalid EC context.
 **/
bool libspdm_ecdsa_verify(void *ec_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          const uint8_t *signature, size_t sig_size)
{
    EVP_PKEY *evp_pkey;
    const EC_KEY *ec_key;
    ECDSA_SIG *ecdsa_sig = NULL;
    BIGNUM *bn_r = NULL;
    BIGNUM *bn_s = NULL;
    int half_size;
    int result;

    if (ec_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    evp_pkey = ((libspdm_key_context *)ec_context)->evp_pkey;
    if (evp_pkey == NULL) {
        return false;
    }

    half_size = evp_pkey_get_half_size(evp_pkey);
    if (half_size < 0) {
        return false;
    }

    if (sig_size != (size_t)(half_size * 2)) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;
    default:
        return false;
    }

    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == NULL) {
        return false;
    }

    /* Convert raw R||S to ECDSA_SIG */
    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL) {
        return false;
    }

    bn_r = BN_bin2bn(signature, half_size, NULL);
    bn_s = BN_bin2bn(signature + half_size, half_size, NULL);
    if (bn_r == NULL || bn_s == NULL) {
        BN_free(bn_r);
        BN_free(bn_s);
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    if (ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s) != 1) {
        BN_free(bn_r);
        BN_free(bn_s);
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }
    /* bn_r and bn_s ownership transferred to ecdsa_sig */

    result = ECDSA_do_verify(message_hash, (int)hash_size, ecdsa_sig, (EC_KEY *)ec_key);

    ECDSA_SIG_free(ecdsa_sig);
    return (result == 1);
}
