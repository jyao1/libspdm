/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) PQC format Handler for AWS-LC.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

int PasswordCallback(char *buf, const int size, const int flag, const void *key);

#if LIBSPDM_ML_DSA_SUPPORT

static bool allocate_key_context(EVP_PKEY *pkey, void **context)
{
    libspdm_key_context *ctx;

    ctx = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (ctx == NULL) {
        return false;
    }
    ctx->evp_pkey = pkey;
    *context = ctx;
    return true;
}

bool libspdm_mldsa_get_private_key_from_pem(const uint8_t *pem_data,
                                            size_t pem_size,
                                            const char *password,
                                            void **dsa_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;

    if (pem_data == NULL || dsa_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    status = false;

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_PQDSA) {
        EVP_PKEY_free(pkey);
        goto done;
    }

    if (!allocate_key_context(pkey, dsa_context)) {
        EVP_PKEY_free(pkey);
        goto done;
    }
    status = true;

done:
    BIO_free(pem_bio);
    return status;
}
#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT
bool libspdm_slhdsa_get_private_key_from_pem(const uint8_t *pem_data,
                                             size_t pem_size,
                                             const char *password,
                                             void **slhdsa_context)
{
    return false;
}
#endif /* LIBSPDM_SLH_DSA_SUPPORT */
