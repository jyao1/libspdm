/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) PQC format Handler for AWS-LC.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#if LIBSPDM_ML_DSA_SUPPORT

bool libspdm_mldsa_get_public_key_from_der(const uint8_t *der_data,
                                           size_t der_size,
                                           void **mldsa_context)
{
    BIO *der_bio;
    EVP_PKEY *pkey;
    libspdm_key_context *ctx;

    if (der_data == NULL || mldsa_context == NULL || der_size > INT_MAX) {
        return false;
    }

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return false;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        BIO_free(der_bio);
        return false;
    }

    pkey = d2i_PUBKEY_bio(der_bio, NULL);
    BIO_free(der_bio);

    if (pkey == NULL) {
        return false;
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_PQDSA) {
        EVP_PKEY_free(pkey);
        return false;
    }

    ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    ctx->evp_pkey = pkey;
    *mldsa_context = ctx;
    return true;
}
#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT
bool libspdm_slhdsa_get_public_key_from_der(const uint8_t *der_data,
                                            size_t der_size,
                                            void **slhdsa_context)
{
    return false;
}
#endif /* LIBSPDM_SLH_DSA_SUPPORT */
