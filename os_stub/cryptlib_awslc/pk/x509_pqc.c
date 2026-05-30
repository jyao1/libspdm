/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * X.509 PQC Certificate Handler Wrapper Implementation for AWS-LC.
 *
 * NOTE: SLH-DSA X.509 operations are not yet supported in AWS-LC.
 **/

#include "internal_crypt_lib.h"
#include "key_context.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Retrieve the ML-DSA public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated ML-DSA context which contain the retrieved
 *                          ML-DSA public key component. Use mldsa_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   ML-DSA public key was retrieved successfully.
 * @retval  false  Fail to retrieve ML-DSA public key from X509 certificate.
 **/
bool libspdm_mldsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                            void **dsa_context)
{
    const uint8_t *temp;
    X509 *x509_cert;
    EVP_PKEY *pkey;
    libspdm_key_context *ctx;

    if (cert == NULL || dsa_context == NULL || cert_size > INT_MAX) {
        return false;
    }

    x509_cert = NULL;
    pkey = NULL;

    temp = cert;
    x509_cert = d2i_X509(NULL, &temp, (long)cert_size);
    if (x509_cert == NULL) {
        return false;
    }

    pkey = X509_get_pubkey(x509_cert);
    X509_free(x509_cert);
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
    *dsa_context = ctx;
    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Retrieve the SLH-DSA public key from one DER-encoded X509 certificate.
 *
 * @retval  false  SLH-DSA not supported by AWS-LC.
 **/
bool libspdm_slhdsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                             void **dsa_context)
{
    return false;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
