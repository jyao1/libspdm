/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * X.509 Certificate Handler Wrapper Implementation.
 **/

#include <stdarg.h>
#include "internal_crypt_lib.h"
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/oid.h>
#include <mbedtls/bignum.h>
#include <string.h>

#if LIBSPDM_CERT_PARSE_SUPPORT

/* OID*/

#define OID_COMMON_NAME       { 0x55, 0x04, 0x03 }
#define OID_ORGANIZATION_NAME { 0x55, 0x04, 0x0A }
#define OID_EXT_KEY_USAGE     { 0x55, 0x1D, 0x25 }
#define OID_BASIC_CONSTRAINTS { 0x55, 0x1D, 0x13 }

static const uint8_t m_libspdm_oid_common_name[] = OID_COMMON_NAME;
static const uint8_t m_libspdm_oid_organization_name[] = OID_ORGANIZATION_NAME;
static const uint8_t m_libspdm_oid_ext_key_usage[] = OID_EXT_KEY_USAGE;
static const uint8_t m_libspdm_oid_basic_constraints[] = OID_BASIC_CONSTRAINTS;

typedef struct {
    const char *name; /* String representation of AttributeType, e.g.
                       * "CN" or "emailAddress". */
    size_t name_len;  /* Length of 'name', without trailing 0 byte. */
    const char *oid;  /* String representation of OID of AttributeType,
                       * as per RFC 5280, Appendix A.1. */
    size_t oid_len;
    int default_tag;  /* The default character encoding used for the
                       * given attribute type, e.g.
                       * MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
} libspdm_x509_subject_descriptor_t;

#define LIBSPDM_ADD_STRLEN( s )     s, sizeof( s ) - 1

/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define LIBSPDM_ECP_PUB_DER_MAX_BYTES   (30 + 2 * MBEDTLS_ECP_MAX_BYTES)

/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define LIBSPDM_RSA_PUB_DER_MAX_BYTES   (38 + 2 * MBEDTLS_MPI_MAX_SIZE)

#define LIBSPDM_MAX_PUBKEY_DER_BUFFER_SIZE (LIBSPDM_RSA_PUB_DER_MAX_BYTES > \
                                            LIBSPDM_ECP_PUB_DER_MAX_BYTES ? \
                                            LIBSPDM_RSA_PUB_DER_MAX_BYTES : \
                                            LIBSPDM_ECP_PUB_DER_MAX_BYTES )

#define LIBSPDM_MAX_SUBJECT_BUFFER_SIZE MBEDTLS_X509_MAX_DN_NAME_SIZE

/**
 * Construct a X509 object from DER-encoded certificate data.
 *
 * If cert is NULL, then return false.
 * If single_x509_cert is NULL, then return false.
 *
 * @param[in]  cert            Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size        The size of certificate data in bytes.
 * @param[out] single_x509_cert  The generated X509 object.
 *
 * @retval     true            The X509 object generation succeeded.
 * @retval     false           The operation failed.
 *
 **/
bool libspdm_x509_construct_certificate(const uint8_t *cert, size_t cert_size,
                                        uint8_t **single_x509_cert)
{
    mbedtls_x509_crt *mbedtls_cert;
    int ret;

    if (cert == NULL || single_x509_cert == NULL || cert_size == 0) {
        return false;
    }

    mbedtls_cert = allocate_pool(sizeof(mbedtls_x509_crt));
    if (mbedtls_cert == NULL) {
        return false;
    }

    mbedtls_x509_crt_init(mbedtls_cert);

    *single_x509_cert = (uint8_t *)(void *)mbedtls_cert;
    ret = mbedtls_x509_crt_parse_der(mbedtls_cert, cert, cert_size);

    return ret == 0;
}

static bool libspdm_x509_construct_certificate_stack_v(uint8_t **x509_stack,
                                                       va_list args)
{
    uint8_t *cert;
    size_t cert_size;
    int ret;

    if (x509_stack == NULL) {
        return false;
    }

    ret = 0;
    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)*x509_stack;
    if (crt == NULL) {
        crt = allocate_pool(sizeof(mbedtls_x509_crt));
        if (crt == NULL) {
            return false;
        }
        mbedtls_x509_crt_init(crt);
        *x509_stack = (uint8_t *)crt;
    }

    for (;;) {

        /* If cert is NULL, then it is the end of the list.*/

        cert = va_arg(args, uint8_t *);
        if (cert == NULL) {
            break;
        }

        cert_size = va_arg(args, size_t);
        if (cert_size == 0) {
            break;
        }

        ret = mbedtls_x509_crt_parse_der(crt, cert, cert_size);

        if (ret != 0) {
            break;
        }
    }
    return ret == 0;
}

/**
 * Construct a X509 stack object from a list of DER-encoded certificate data.
 *
 * If x509_stack is NULL, then return false.
 *
 * @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
 *                            On output, pointer to the X509 stack object with new
 *                            inserted X509 certificate.
 * @param           ...        A list of DER-encoded single certificate data followed
 *                            by certificate size. A NULL terminates the list. The
 *                            pairs are the arguments to libspdm_x509_construct_certificate().
 *
 * @retval     true            The X509 stack construction succeeded.
 * @retval     false           The construction operation failed.
 *
 **/
bool libspdm_x509_construct_certificate_stack(uint8_t **x509_stack, ...)
{
    va_list args;
    bool result;

    va_start(args, x509_stack);
    result = libspdm_x509_construct_certificate_stack_v(x509_stack, args);
    va_end(args);
    return result;
}

/**
 * Release the specified X509 object.
 *
 * If x509_cert is NULL, then return early.
 *
 * @param[in]  x509_cert  Pointer to the X509 object to be released.
 *
 **/
void libspdm_x509_free(void *x509_cert)
{
    if (x509_cert == NULL) {
        return;
    }

    mbedtls_x509_crt_free(x509_cert);
    free_pool(x509_cert);
}

/**
 * Release the specified X509 stack object.
 *
 * If x509_stack is NULL, then return early.
 *
 * @param[in]  x509_stack  Pointer to the X509 stack object to be released.
 *
 **/
void libspdm_x509_stack_free(void *x509_stack)
{
    if (x509_stack == NULL) {
        return;
    }

    mbedtls_x509_crt_free(x509_stack);
}

/**
 * Retrieve the tag and length of the tag.
 *
 * @param ptr      The position in the ASN.1 data
 * @param end      end of data
 * @param length   The variable that will receive the length
 * @param tag      The expected tag
 *
 * @retval      true   Get tag successful
 * @retval      false  Failed to get tag or tag not match
 **/
bool libspdm_asn1_get_tag(uint8_t **ptr, const uint8_t *end, size_t *length,
                          uint32_t tag)
{
    if (mbedtls_asn1_get_tag(ptr, end, length, (int32_t)tag) == 0) {
        return true;
    } else {
        return false;
    }
}

/**
 * Retrieve the subject bytes from one X.509 certificate.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     cert_subject  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] subject_size  The size in bytes of the cert_subject buffer on input,
 *                             and the size of buffer returned cert_subject on output.
 *
 * If cert is NULL, then return false.
 * If subject_size is NULL, then return false.
 *
 * @retval  true   If the subject_size is not equal 0. The certificate subject retrieved successfully.
 * @retval  true   If the subject_size is equal 0. The certificate parse successful. But the cert doesn't have subject.
 * @retval  false  If the subject_size is not equal 0. The certificate subject retrieved successfully.But the subject_size is too small for the result.
 * @retval  false  If the subject_size is equal 0. Invalid certificate.
 **/
bool libspdm_x509_get_subject_name(const uint8_t *cert, size_t cert_size,
                                   uint8_t *cert_subject,
                                   size_t *subject_size)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;

    /* Check input parameters.*/
    if (cert == NULL || cert == 0 || subject_size == NULL) {
        if (subject_size != NULL) {
            *subject_size = 0;
        }
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        if (*subject_size < crt.subject_raw.len) {
            *subject_size = crt.subject_raw.len;
            status = false;
            goto cleanup;
        }
        if (cert_subject != NULL) {
            libspdm_copy_mem(cert_subject, *subject_size,
                             crt.subject_raw.p, crt.subject_raw.len);
        }
        *subject_size = crt.subject_raw.len;
        status = true;
    } else {
        *subject_size = 0;
    }

cleanup:
    mbedtls_x509_crt_free(&crt);

    return status;
}

bool
libspdm_internal_x509_get_nid_name(mbedtls_x509_name *name, const uint8_t *oid,
                                   size_t oid_size, char *common_name,
                                   size_t *common_name_size)
{
    const mbedtls_asn1_named_data *data;

    data = mbedtls_asn1_find_named_data(name, (const char *)oid, oid_size);
    if (data != NULL) {
        if (*common_name_size <= data->val.len) {
            *common_name_size = data->val.len + 1;
            return false;
        }
        if (common_name != NULL) {
            libspdm_copy_mem(common_name, *common_name_size, data->val.p, data->val.len);
            common_name[data->val.len] = '\0';
        }
        *common_name_size = data->val.len + 1;
        return true;
    } else {
        *common_name_size = 0;
        return false;
    }
}

bool
libspdm_internal_x509_get_subject_nid_name(const uint8_t *cert, size_t cert_size,
                                           const uint8_t *oid, size_t oid_size,
                                           char *common_name,
                                           size_t *common_name_size)
{
    mbedtls_x509_crt crt;
    int ret;
    mbedtls_x509_name *name;
    bool status;

    if (cert == NULL) {
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        name = &(crt.subject);
        status = libspdm_internal_x509_get_nid_name(
            name, oid, oid_size, common_name, common_name_size);
    }

    mbedtls_x509_crt_free(&crt);

    return status;
}

bool
libspdm_internal_x509_get_issuer_nid_name(const uint8_t *cert, size_t cert_size,
                                          const uint8_t *oid, size_t oid_size,
                                          char *common_name,
                                          size_t *common_name_size)
{
    mbedtls_x509_crt crt;
    int ret;
    mbedtls_x509_name *name;
    bool status;

    if (cert == NULL) {
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        name = &(crt.issuer);
        status = libspdm_internal_x509_get_nid_name(
            name, oid, oid_size, common_name, common_name_size);
    }

    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     common_name       buffer to contain the retrieved certificate common
 *                                 name string. At most common_name_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
 *                                 and the size of buffer returned common_name on output.
 *                                 If common_name is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate common_name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If common_name_size is NULL.
 *                                 If common_name is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no common_name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool libspdm_x509_get_common_name(const uint8_t *cert, size_t cert_size,
                                  char *common_name,
                                  size_t *common_name_size)
{
    return libspdm_internal_x509_get_subject_nid_name(
        cert, cert_size, (const uint8_t *)m_libspdm_oid_common_name,
        sizeof(m_libspdm_oid_common_name), common_name, common_name_size);
}

/**
 * Retrieve the organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate organization
 *                                 name string. At most name_buffer_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Organization name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_organization_name(const uint8_t *cert, size_t cert_size,
                                   char *name_buffer,
                                   size_t *name_buffer_size)
{
    return libspdm_internal_x509_get_subject_nid_name(
        cert, cert_size, m_libspdm_oid_organization_name,
        sizeof(m_libspdm_oid_organization_name), name_buffer, name_buffer_size);
}

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] rsa_context   Pointer to newly generated RSA context which contain the retrieved
 *                         RSA public key component. Use libspdm_rsa_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA public key was retrieved successfully.
 * @retval  false  Fail to retrieve RSA public key from X509 certificate.
 *
 **/
bool libspdm_rsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **rsa_context)
{
    mbedtls_x509_crt crt;
    mbedtls_rsa_context *rsa;
    int ret;

    mbedtls_x509_crt_init(&crt);

    if (mbedtls_x509_crt_parse_der(&crt, cert, cert_size) != 0) {
        return false;
    }

    if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_RSA) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    rsa = libspdm_rsa_new();
    if (rsa == NULL) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(crt.pk));
    if (ret != 0) {
        libspdm_rsa_free(rsa);
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    mbedtls_x509_crt_free(&crt);

    *rsa_context = rsa;
    return true;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

/**
 * Retrieve the EC public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] ec_context    Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC public key was retrieved successfully.
 * @retval  false  Fail to retrieve EC public key from X509 certificate.
 *
 **/
bool libspdm_ec_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                         void **ec_context)
{
    mbedtls_x509_crt crt;
    mbedtls_ecdh_context *ecdh;
    int ret;

    mbedtls_x509_crt_init(&crt);

    if (mbedtls_x509_crt_parse_der(&crt, cert, cert_size) != 0) {
        return false;
    }

    if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_ECKEY) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    ecdh = allocate_zero_pool(sizeof(mbedtls_ecdh_context));
    if (ecdh == NULL) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    mbedtls_ecdh_init(ecdh);

    ret = mbedtls_ecdh_get_params(ecdh, mbedtls_pk_ec(crt.pk),
                                  MBEDTLS_ECDH_OURS);
    if (ret != 0) {
        mbedtls_ecdh_free(ecdh);
        free_pool(ecdh);
        mbedtls_x509_crt_free(&crt);
        return false;
    }
    mbedtls_x509_crt_free(&crt);

    *ec_context = ecdh;
    return true;
}

/**
 * Retrieve the Ed public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] ecd_context    Pointer to newly generated Ed DSA context which contain the retrieved
 *                         Ed public key component. Use libspdm_ecd_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed public key was retrieved successfully.
 * @retval  false  Fail to retrieve Ed public key from X509 certificate.
 *
 **/
bool libspdm_ecd_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **ecd_context)
{
    return false;
}

/**
 * Retrieve the sm2 public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] sm2_context   Pointer to newly generated sm2 context which contain the retrieved
 *                         sm2 public key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   sm2 public key was retrieved successfully.
 * @retval  false  Fail to retrieve sm2 public key from X509 certificate.
 *
 **/
bool libspdm_sm2_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **sm2_context)
{
    return false;
}

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate to be verified.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[in]      ca_cert       Pointer to the DER-encoded trusted CA certificate.
 * @param[in]      ca_cert_size   size of the CA Certificate in bytes.
 *
 * If cert is NULL, then return false.
 * If ca_cert is NULL, then return false.
 *
 * @retval  true   The certificate was issued by the trusted CA.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                trusted CA.
 *
 **/
bool libspdm_x509_verify_cert(const uint8_t *cert, size_t cert_size,
                              const uint8_t *ca_cert, size_t ca_cert_size)
{
    int ret;
    mbedtls_x509_crt ca, end;
    uint32_t v_flag = 0;
    mbedtls_x509_crt_profile profile = { 0 };

    if (cert == NULL || ca_cert == NULL) {
        return false;
    }

    libspdm_copy_mem(&profile, sizeof(profile),
                     &mbedtls_x509_crt_profile_default,
                     sizeof(mbedtls_x509_crt_profile));

    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&end);

    ret = mbedtls_x509_crt_parse_der(&ca, ca_cert, ca_cert_size);

    if (ret == 0) {
        ret = mbedtls_x509_crt_parse_der(&end, cert, cert_size);
    }

    if (ret == 0) {
        ret = mbedtls_x509_crt_verify_with_profile(
            &end, &ca, NULL, &profile, NULL, &v_flag, NULL, NULL);
    }

    mbedtls_x509_crt_free(&ca);
    mbedtls_x509_crt_free(&end);

    return ret == 0;
}

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                  where the first certificate is signed by the Root
 *                                  Certificate or is the Root Certificate itself. and
 *                                  subsequent certificate is signed by the preceding
 *                                  certificate.
 * @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.
 *
 * @param[in]      root_cert          Trusted Root Certificate buffer
 *
 * @param[in]      root_cert_length    Trusted Root Certificate buffer length
 *
 * @retval  true   All certificates were issued by the first certificate in X509Certchain.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                trusted CA.
 **/
bool libspdm_x509_verify_cert_chain(const uint8_t *root_cert, size_t root_cert_length,
                                    const uint8_t *cert_chain, size_t cert_chain_length)
{
    size_t asn1_len;
    size_t preceding_cert_len;
    const uint8_t *preceding_cert;
    size_t current_cert_len;
    const unsigned char *current_cert;
    const unsigned char *tmp_ptr;
    int ret;
    bool verify_flag;

    verify_flag = false;
    preceding_cert = root_cert;
    preceding_cert_len = root_cert_length;

    current_cert = (const unsigned char *)cert_chain;


    /* Get Current certificate from certificates buffer and Verify with preceding cert*/

    do {
        tmp_ptr = current_cert;
        ret = mbedtls_asn1_get_tag(
            &tmp_ptr, cert_chain + cert_chain_length, &asn1_len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            if (current_cert < cert_chain + cert_chain_length) {
                verify_flag = false;
            }
            break;
        }

        current_cert_len = asn1_len + (tmp_ptr - current_cert);

        if (current_cert + current_cert_len > cert_chain + cert_chain_length) {
            verify_flag = false;
            break;
        }

        if (libspdm_x509_verify_cert(current_cert, current_cert_len,
                                     preceding_cert,
                                     preceding_cert_len) == false) {
            verify_flag = false;
            break;
        } else {
            verify_flag = true;
        }


        /* Save preceding certificate*/

        preceding_cert = current_cert;
        preceding_cert_len = current_cert_len;


        /* Move current certificate to next;*/

        current_cert = current_cert + current_cert_len;
    } while (true);

    return verify_flag;
}

/**
 * Get one X509 certificate from cert_chain.
 *
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                  where the first certificate is signed by the Root
 *                                  Certificate or is the Root Certificate itself. and
 *                                  subsequent certificate is signed by the preceding
 *                                  certificate.
 * @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.
 *
 * @param[in]      cert_index         index of certificate.
 *
 * @param[out]     cert              The certificate at the index of cert_chain.
 * @param[out]     cert_length        The length certificate at the index of cert_chain.
 *
 * @retval  true   Success.
 * @retval  false  Failed to get certificate from certificate chain.
 **/
bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                           size_t cert_chain_length,
                                           const int32_t cert_index, const uint8_t **cert,
                                           size_t *cert_length)
{
    size_t asn1_len;
    int32_t current_index;
    size_t current_cert_len;
    const unsigned char *current_cert;
    const unsigned char *tmp_ptr;
    int ret;

    current_cert_len = 0;

    /* Check input parameters.*/

    if ((cert_chain == NULL) || (cert == NULL) || (cert_index < -1) ||
        (cert_length == NULL)) {
        return false;
    }

    current_cert = (const unsigned char *)cert_chain;
    current_index = -1;


    /* Traverse the certificate chain*/

    while (true) {

        /* Get asn1 tag len*/

        tmp_ptr = current_cert;
        ret = mbedtls_asn1_get_tag(
            &tmp_ptr, cert_chain + cert_chain_length, &asn1_len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            break;
        }

        current_cert_len = asn1_len + (tmp_ptr - current_cert);
        if (current_cert + current_cert_len > cert_chain + cert_chain_length) {
            return false;
        }

        current_index++;

        if (current_index == cert_index) {
            *cert = current_cert;
            *cert_length = current_cert_len;
            return true;
        }


        /* Move to next*/

        current_cert = current_cert + current_cert_len;
    }


    /* If cert_index is -1, Return the last certificate*/

    if (cert_index == -1 && current_index >= 0) {
        *cert = current_cert - current_cert_len;
        *cert_length = current_cert_len;
        return true;
    }

    return false;
}

/**
 * Retrieve the TBSCertificate from one given X.509 certificate.
 *
 * @param[in]      cert         Pointer to the given DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     tbs_cert      DER-Encoded to-Be-Signed certificate.
 * @param[out]     tbs_cert_size  size of the TBS certificate in bytes.
 *
 * If cert is NULL, then return false.
 * If tbs_cert is NULL, then return false.
 * If tbs_cert_size is NULL, then return false.
 *
 * @retval  true   The TBSCertificate was retrieved successfully.
 * @retval  false  Invalid X.509 certificate.
 *
 **/
bool libspdm_x509_get_tbs_cert(const uint8_t *cert, size_t cert_size,
                               uint8_t **tbs_cert, size_t *tbs_cert_size)
{
    return false;
}

/**
 * Retrieve the version from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     version      Pointer to the retrieved version integer.
 *
 * @retval RETURN_SUCCESS           The certificate version retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If  cert is NULL or cert_size is Zero.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool libspdm_x509_get_version(const uint8_t *cert, size_t cert_size,
                              size_t *version)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;

    if (cert == NULL) {
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        *version = crt.version - 1;
        status = true;
    }

    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the serialNumber from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     serial_number  Pointer to the retrieved certificate serial_number bytes.
 * @param[in, out] serial_number_size  The size in bytes of the serial_number buffer on input,
 *                             and the size of buffer returned serial_number on output.
 *
 * @retval RETURN_SUCCESS           The certificate serialNumber retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL or cert_size is Zero.
 *                                 If serial_number_size is NULL.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no serial_number exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the serial_number is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 serial_number_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_serial_number(const uint8_t *cert, size_t cert_size,
                                    uint8_t *serial_number,
                                    size_t *serial_number_size)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;

    if (cert == NULL) {
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        if (*serial_number_size <= crt.serial.len) {
            *serial_number_size = crt.serial.len + 1;
            status = false;
            goto cleanup;
        }
        if (serial_number != NULL) {
            libspdm_copy_mem(serial_number, *serial_number_size, crt.serial.p, crt.serial.len);
            serial_number[crt.serial.len] = '\0';
        }
        *serial_number_size = crt.serial.len + 1;
        status = true;
    }
cleanup:
    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the issuer bytes from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If issuer_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     cert_issuer  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] issuer_size  The size in bytes of the cert_issuer buffer on input,
 *                             and the size of buffer returned cert_issuer on output.
 *
 * @retval  true   If the issuer_size is not equal 0. The certificate issuer retrieved successfully.
 * @retval  true   If the issuer_size is equal 0. The certificate parse successful. But the cert doesn't have issuer.
 * @retval  false  If the issuer_size is not equal 0. The certificate issuer retrieved successfully. But the issuer_size is too small for the result.
 * @retval  false  If the issuer_size is equal 0. Invalid certificate.
 *
 **/
bool libspdm_x509_get_issuer_name(const uint8_t *cert, size_t cert_size,
                                  uint8_t *cert_issuer,
                                  size_t *issuer_size)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;

    /* Check input parameters.*/
    if (cert == NULL || cert_size == 0 || issuer_size == NULL) {
        if (issuer_size != NULL) {
            *issuer_size = 0;
        }
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        if (*issuer_size < crt.issuer_raw.len) {
            *issuer_size = crt.issuer_raw.len;
            status = false;
            goto cleanup;
        }
        if (cert_issuer != NULL) {
            libspdm_copy_mem(cert_issuer, *issuer_size, crt.issuer_raw.p, crt.issuer_raw.len);
        }
        *issuer_size = crt.issuer_raw.len;
        status = true;
    } else {
        *issuer_size = 0;
    }

cleanup:
    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the issuer common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     common_name       buffer to contain the retrieved certificate issuer common
 *                                 name string. At most common_name_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
 *                                 and the size of buffer returned common_name on output.
 *                                 If common_name is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate Issuer common_name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If common_name_size is NULL.
 *                                 If common_name is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no common_name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_issuer_common_name(const uint8_t *cert, size_t cert_size,
                                    char *common_name,
                                    size_t *common_name_size)
{
    return libspdm_internal_x509_get_issuer_nid_name(cert, cert_size,
                                                     m_libspdm_oid_common_name,
                                                     sizeof(m_libspdm_oid_common_name),
                                                     common_name, common_name_size);
}

/**
 * Retrieve the issuer organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate issuer organization
 *                                 name string. At most name_buffer_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate issuer Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Organization name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_issuer_orgnization_name(const uint8_t *cert, size_t cert_size,
                                         char *name_buffer,
                                         size_t *name_buffer_size)
{
    return libspdm_internal_x509_get_issuer_nid_name(
        cert, cert_size, m_libspdm_oid_organization_name,
        sizeof(m_libspdm_oid_organization_name), name_buffer, name_buffer_size);
}

#if LIBSPDM_ADDITIONAL_CHECK_CERT
/**
 * Retrieve the signature algorithm from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     oid              signature algorithm Object identifier buffer.
 * @param[in,out]  oid_size          signature algorithm Object identifier buffer size
 *
 * @retval  true    if the oid_size is equal 0, the cert parse successfully, but cert doesn't have signature algo.
 * @retval  true    if the oid_size is not equal 0, the cert parse and get signature algo successfully.
 * @retval  false   if the oid_size is equal 0, the cert parse failed.
 * @retval  false   if the oid_size is not equal 0, the cert parse and get signature algo successfully, but the input buffer size is small.
 **/
bool libspdm_x509_get_signature_algorithm(const uint8_t *cert,
                                          size_t cert_size, uint8_t *oid,
                                          size_t *oid_size)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;

    /* Check input parameters.*/
    if (cert == NULL || cert_size == 0 || oid_size == NULL) {
        if (oid_size != NULL) {
            *oid_size = 0;
        }
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        if (*oid_size < crt.sig_oid.len) {
            *oid_size = crt.serial.len;
            status = false;
            goto cleanup;
        }
        if (oid != NULL) {
            libspdm_copy_mem(oid, *oid_size, crt.sig_oid.p, crt.sig_oid.len);
        }
        *oid_size = crt.sig_oid.len;
        status = true;
    } else {
        *oid_size = 0;
    }

cleanup:
    mbedtls_x509_crt_free(&crt);

    return status;
}
#endif /* LIBSPDM_ADDITIONAL_CHECK_CERT */

/**
 * Find first Extension data match with given OID
 *
 * @param[in]      start             Pointer to the DER-encoded extensions data
 * @param[in]      end               extensions data size in bytes
 * @param[in ]     oid               OID for match
 * @param[in ]     oid_size           OID size in bytes
 * @param[out]     find_extension_data output matched extension data.
 * @param[out]     find_extension_data_len matched extension data size.
 *
 **/
static bool
libspdm_internal_x509_find_extension_data(uint8_t *start, uint8_t *end, const uint8_t *oid,
                                          size_t oid_size, uint8_t **find_extension_data,
                                          size_t *find_extension_data_len)
{
    uint8_t *ptr;
    uint8_t *extension_ptr;
    size_t obj_len;
    int ret;
    bool status;
    size_t find_extension_len;
    size_t header_len;

    /*If no Extension entry match oid*/
    status = false;
    ptr = start;

    ret = 0;

    while (true) {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    bool DEFAULT false,
         *      extnValue   OCTET STRING  }
         */
        extension_ptr = ptr;
        ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
                                   MBEDTLS_ASN1_CONSTRUCTED |
                                   MBEDTLS_ASN1_SEQUENCE);
        if (ret == 0) {
            header_len = (size_t)(ptr - extension_ptr);
            find_extension_len = obj_len;
            /* Get Object Identifier*/
            ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
                                       MBEDTLS_ASN1_OID);
        } else {
            break;
        }

        if (ret == 0 && libspdm_consttime_is_mem_equal(ptr, oid, oid_size)) {
            ptr += obj_len;

            ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
                                       MBEDTLS_ASN1_BOOLEAN);
            if (ret == 0) {
                ptr += obj_len;
            }

            ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
                                       MBEDTLS_ASN1_OCTET_STRING);
        } else {
            ret = 1;
        }

        if (ret == 0) {
            *find_extension_data = ptr;
            *find_extension_data_len = obj_len;
            status = true;
            break;
        }

        /* move to next*/
        ptr = extension_ptr + header_len + find_extension_len;
        ret = 0;
    }

    return status;
}

/**
 * Retrieve Extension data from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[in]      oid              Object identifier buffer
 * @param[in]      oid_size          Object identifier buffer size
 * @param[out]     extension_data    Extension bytes.
 * @param[in, out] extension_data_size Extension bytes size.
 *
 * @retval true   If the returned extension_data_size == 0, it means that cert and oid are valid, but the oid extension is not found;
 *                If the returned extension_data_size != 0, it means that cert and oid are valid, and the oid extension is found;
 * @retval false  If the returned extension_data_size == 0, it means that cert or oid are invalid;
 *                If the returned extension_data_size != 0, it means that cert and oid are valid, and the oid extension is found,
 *                                                          but the store buffer is too small.
 **/
bool libspdm_x509_get_extension_data(const uint8_t *cert, size_t cert_size,
                                     const uint8_t *oid, size_t oid_size,
                                     uint8_t *extension_data,
                                     size_t *extension_data_size)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;
    uint8_t *ptr;
    uint8_t *end;
    size_t obj_len;

    ptr = NULL;
    end = NULL;
    obj_len = 0;

    if (cert == NULL || cert_size == 0 || oid == NULL || oid_size == 0 ||
        extension_data_size == NULL) {
        if (extension_data_size != NULL) {
            *extension_data_size = 0;
        }
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        ptr = crt.v3_ext.p;
        end = crt.v3_ext.p + crt.v3_ext.len;
        ret = mbedtls_asn1_get_tag(&ptr, end, &obj_len,
                                   MBEDTLS_ASN1_CONSTRUCTED |
                                   MBEDTLS_ASN1_SEQUENCE);
    }

    if (ret == 0) {
        status = libspdm_internal_x509_find_extension_data(
            ptr, end, oid, oid_size, &ptr, &obj_len);
        if (!status) {
            status = true;
            *extension_data_size = 0;
            goto cleanup;
        }
    }

    if (status) {
        if (*extension_data_size < obj_len) {
            *extension_data_size = obj_len;
            status = false;
            goto cleanup;
        }
        if (oid != NULL) {
            libspdm_copy_mem(extension_data, *extension_data_size, ptr, obj_len);
        }
        *extension_data_size = obj_len;
    } else {
        *extension_data_size = 0;
    }

cleanup:
    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the Validity from one X.509 certificate
 *
 * If cert is NULL, then return false.
 * If CertIssuerSize is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     from         notBefore Pointer to date_time object.
 * @param[in,out]  from_size     notBefore date_time object size.
 * @param[out]     to           notAfter Pointer to date_time object.
 * @param[in,out]  to_size       notAfter date_time object size.
 *
 * Note: libspdm_x509_compare_date_time to compare date_time object
 *      x509SetDateTime to get a date_time object from a date_time_str
 *
 * @retval  true   The certificate Validity retrieved successfully.
 * @retval  false  Invalid certificate, or Validity retrieve failed.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_x509_get_validity(const uint8_t *cert, size_t cert_size,
                               uint8_t *from, size_t *from_size, uint8_t *to,
                               size_t *to_size)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;
    size_t t_size;
    size_t f_size;
    mbedtls_x509_time zero_time;

    /* Check input parameters.*/
    if (cert == NULL || from_size == NULL || to_size == NULL ||
        cert_size == 0) {
        if (from_size != NULL) {
            *from_size = 0;
        }
        if (to_size != NULL) {
            *to_size = 0;
        }
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);
    libspdm_zero_mem(&zero_time, sizeof(mbedtls_x509_time));

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        f_size = sizeof(mbedtls_x509_time);
        if ((libspdm_consttime_is_mem_equal(&zero_time, &(crt.valid_from), f_size)) &&
            (libspdm_consttime_is_mem_equal(&zero_time, &(crt.valid_to), f_size))) {
            *from_size = 0;
            *to_size = 0;
            status = true;
            goto done;
        }

        if (*from_size < f_size) {
            *from_size = f_size;
            goto done;
        }
        if (from != NULL) {
            libspdm_copy_mem(from, *from_size, &(crt.valid_from), f_size);
        }
        *from_size = f_size;

        t_size = sizeof(mbedtls_x509_time);
        if (*to_size < t_size) {
            *to_size = t_size;
            goto done;
        }
        if (to != NULL) {
            libspdm_copy_mem(to, *to_size, &(crt.valid_to),
                             sizeof(mbedtls_x509_time));
        }
        *to_size = t_size;
        status = true;
    } else {
        *from_size = 0;
        *to_size = 0;
    }

done:
    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the key usage from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     usage            key usage (LIBSPDM_CRYPTO_X509_KU_*)
 *
 * @retval  true   if the usage is no equal 0. The certificate key usage retrieved successfully.
 * @retval  true   if the usage is equal 0. The certificate parse successfully, but the cert doesn't have key usage.
 * @retval  false  Invalid certificate, or usage is NULL.
 **/
bool libspdm_x509_get_key_usage(const uint8_t *cert, size_t cert_size,
                                size_t *usage)
{
    mbedtls_x509_crt crt;
    int ret;
    bool status;

    /* Check input parameters.*/
    if (cert == NULL || cert_size == 0 || usage == NULL) {
        if (usage != NULL) {
            *usage = 0;
        }
        return false;
    }

    status = false;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0) {
        *usage = crt.MBEDTLS_PRIVATE(key_usage);
        status = true;
    } else {
        *usage = 0;
    }
    mbedtls_x509_crt_free(&crt);

    return status;
}

/**
 * Retrieve the Extended key usage from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     usage            key usage bytes.
 * @param[in, out] usage_size        key usage buffer sizs in bytes.
 *
 * @retval true   If the returned usage_size == 0, it means that cert and oid are valid, but the Extended key usage is not found;
 *                If the returned usage_size != 0, it means that cert and oid are valid, and the Extended key usage is found;
 * @retval false  If the returned usage_size == 0, it means that cert or oid are invalid;
 *                If the returned usage_size != 0, it means that cert and oid are valid, and the Extended key usage is found,
 *                                                 but the store buffer is too small.
 **/
bool libspdm_x509_get_extended_key_usage(const uint8_t *cert,
                                         size_t cert_size, uint8_t *usage,
                                         size_t *usage_size)
{
    bool status;

    if (cert == NULL || cert_size == 0 || usage_size == NULL) {
        return false;
    }

    status = libspdm_x509_get_extension_data(cert, cert_size,
                                             m_libspdm_oid_ext_key_usage,
                                             sizeof(m_libspdm_oid_ext_key_usage), usage,
                                             usage_size);

    return status;
}

/**
 * Retrieve the basic constraints from one X.509 certificate.
 *
 * @param[in]      cert                     Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size                size of the X509 certificate in bytes.
 * @param[out]     basic_constraints        basic constraints bytes.
 * @param[in, out] basic_constraints_size   basic constraints buffer sizs in bytes.
 *
 * @retval true   If the returned basic_constraints_size == 0, it means that cert and oid are valid, but the basic_constraints is not found;
 *                If the returned basic_constraints_size != 0, it means that cert and oid are valid, and the basic_constraints is found;
 * @retval false  If the returned basic_constraints_size == 0, it means that cert or oid are invalid;
 *                If the returned basic_constraints_size != 0, it means that cert and oid are valid, and the basic_constraints is found,
 *                                                             but the store buffer is too small.
 **/
bool libspdm_x509_get_extended_basic_constraints(const uint8_t *cert,
                                                 size_t cert_size,
                                                 uint8_t *basic_constraints,
                                                 size_t *basic_constraints_size)
{
    bool status;

    if (cert == NULL || cert_size == 0 || basic_constraints_size == NULL) {
        return false;
    }

    status = libspdm_x509_get_extension_data(cert, cert_size,
                                             m_libspdm_oid_basic_constraints,
                                             sizeof(m_libspdm_oid_basic_constraints),
                                             basic_constraints,
                                             basic_constraints_size);
    return status;
}

/**
 * Return 0 if before <= after, 1 otherwise
 **/
static int32_t libspdm_internal_x509_check_time(const mbedtls_x509_time *before,
                                                const mbedtls_x509_time *after)
{
    if (before->year > after->year) {
        return (1);
    }

    if (before->year == after->year && before->mon > after->mon) {
        return (1);
    }

    if (before->year == after->year && before->mon == after->mon &&
        before->day > after->day) {
        return (1);
    }

    if (before->year == after->year && before->mon == after->mon &&
        before->day == after->day && before->hour > after->hour) {
        return (1);
    }

    if (before->year == after->year && before->mon == after->mon &&
        before->day == after->day && before->hour == after->hour &&
        before->min > after->min) {
        return (1);
    }

    if (before->year == after->year && before->mon == after->mon &&
        before->day == after->day && before->hour == after->hour &&
        before->min == after->min && before->sec > after->sec) {
        return (1);
    }

    return (0);
}

static int32_t libspdm_internal_atoi(const char *p_start, char const *p_end)
{
    const char *p = p_start;
    int32_t k = 0;
    while (p < p_end) {

        /* k = k * 2³ + k * 2¹ = k * 8 + k * 2 = k * 10*/

        k = (k << 3) + (k << 1) + (*p) - '0';
        p++;
    }
    return k;
}

/**
 * format a date_time object into DataTime buffer
 *
 * If date_time_str is NULL, then return false.
 * If date_time_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      date_time_str      date_time string like YYYYMMDDhhmmssZ
 *                                 Ref: https://www.w3.org/TR/NOTE-datetime
 *                                 Z stand for UTC time
 * @param[out]     date_time         Pointer to a date_time object.
 * @param[in,out]  date_time_size     date_time object buffer size.
 *
 * @retval RETURN_SUCCESS           The date_time object create successfully.
 * @retval RETURN_INVALID_PARAMETER If date_time_str is NULL.
 *                                 If date_time_size is NULL.
 *                                 If date_time is not NULL and *date_time_size is 0.
 *                                 If year month day hour minute second combination is invalid datetime.
 * @retval RETURN_BUFFER_TOO_SMALL  If the date_time is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 date_time_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_set_date_time(const char *date_time_str, void *date_time, size_t *date_time_size)
{
    mbedtls_x509_time dt;

    int32_t year;
    int32_t month;
    int32_t day;
    int32_t hour;
    int32_t minute;
    int32_t second;
    bool status;
    const char *p;

    p = date_time_str;

    year = libspdm_internal_atoi(p, p + 4);
    p += 4;
    month = libspdm_internal_atoi(p, p + 2);
    p += 2;
    day = libspdm_internal_atoi(p, p + 2);
    p += 2;
    hour = libspdm_internal_atoi(p, p + 2);
    p += 2;
    minute = libspdm_internal_atoi(p, p + 2);
    p += 2;
    second = libspdm_internal_atoi(p, p + 2);
    p += 2;
    dt.year = (int)year;
    dt.mon = (int)month;
    dt.day = (int)day;
    dt.hour = (int)hour;
    dt.min = (int)minute;
    dt.sec = (int)second;

    if (*date_time_size < sizeof(mbedtls_x509_time)) {
        *date_time_size = sizeof(mbedtls_x509_time);
        status = false;
        goto cleanup;
    }
    if (date_time != NULL) {
        libspdm_copy_mem(date_time, *date_time_size, &dt, sizeof(mbedtls_x509_time));
    }
    *date_time_size = sizeof(mbedtls_x509_time);
    status = true;
cleanup:
    return status;
}

/**
 * Compare date_time1 object and date_time2 object.
 *
 * If date_time1 is NULL, then return -2.
 * If date_time2 is NULL, then return -2.
 * If date_time1 == date_time2, then return 0
 * If date_time1 > date_time2, then return 1
 * If date_time1 < date_time2, then return -1
 *
 * @param[in]      date_time1         Pointer to a date_time Object
 * @param[in]      date_time2         Pointer to a date_time Object
 *
 * @retval  0      If date_time1 == date_time2
 * @retval  1      If date_time1 > date_time2
 * @retval  -1     If date_time1 < date_time2
 **/
int32_t libspdm_x509_compare_date_time(const void *date_time1, const void *date_time2)
{
    if (date_time1 == NULL || date_time2 == NULL) {
        return -2;
    }
    if (libspdm_consttime_is_mem_equal(date_time2, date_time1, sizeof(mbedtls_x509_time))) {
        return 0;
    }
    if (libspdm_internal_x509_check_time((const mbedtls_x509_time *)date_time1,
                                         (const mbedtls_x509_time *)date_time2) == 0) {
        return -1;
    } else {
        return 1;
    }
}

static bool libspdm_convert_subject_to_string(uint8_t *ptr, size_t obj_len,
                                              uint8_t *buffer, int32_t buff_len)
{
    bool ret;
    uint8_t *end;
    uint8_t *internal_p;

    libspdm_x509_subject_descriptor_t *cur;
    /* X.509 DN attributes from RFC 5280, Appendix A.1. */
    libspdm_x509_subject_descriptor_t x509_attrs[] =
    {
        { LIBSPDM_ADD_STRLEN( "CN" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_CN ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "C" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_COUNTRY ),
          MBEDTLS_ASN1_PRINTABLE_STRING },
        { LIBSPDM_ADD_STRLEN( "O" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_ORGANIZATION ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "L" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_LOCALITY ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "R" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_PKCS9_EMAIL ),
          MBEDTLS_ASN1_IA5_STRING },
        { LIBSPDM_ADD_STRLEN( "OU" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_ORG_UNIT ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "ST" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_STATE ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "emailAddress" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_PKCS9_EMAIL ),
          MBEDTLS_ASN1_IA5_STRING },
        { LIBSPDM_ADD_STRLEN( "serialNumber" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_SERIAL_NUMBER ),
          MBEDTLS_ASN1_PRINTABLE_STRING },
        { LIBSPDM_ADD_STRLEN( "postalAddress" ),
          LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_POSTAL_ADDRESS ), MBEDTLS_ASN1_PRINTABLE_STRING },
        { LIBSPDM_ADD_STRLEN( "postalCode" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_POSTAL_CODE ),
          MBEDTLS_ASN1_PRINTABLE_STRING },
        { LIBSPDM_ADD_STRLEN( "dnQualifier" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_DN_QUALIFIER ),
          MBEDTLS_ASN1_PRINTABLE_STRING },
        { LIBSPDM_ADD_STRLEN( "title" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_TITLE ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "SN" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_SUR_NAME ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "GN" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_GIVEN_NAME ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "initials" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_INITIALS ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "pseudonym" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_PSEUDONYM ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "generationQualifier" ),
          LIBSPDM_ADD_STRLEN( MBEDTLS_OID_AT_GENERATION_QUALIFIER ),
          MBEDTLS_ASN1_UTF8_STRING },
        { LIBSPDM_ADD_STRLEN( "DC" ), LIBSPDM_ADD_STRLEN( MBEDTLS_OID_DOMAIN_COMPONENT ),
          MBEDTLS_ASN1_IA5_STRING },
        { NULL, 0, NULL, 0, MBEDTLS_ASN1_NULL }
    };

    end = ptr + obj_len;

    while(ptr != end) {
        /*SET*/
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SET | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }
        internal_p = ptr;
        /*move to next SET*/
        ptr += obj_len;

        /*sequence*/
        ret = libspdm_asn1_get_tag(&internal_p, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (!ret) {
            return false;
        }

        /*OID*/
        ret = libspdm_asn1_get_tag(&internal_p, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
        if (!ret) {
            return false;
        }

        for (cur = x509_attrs; cur->name != NULL; cur++) {
            if ((cur->oid_len == obj_len) &&
                (libspdm_consttime_is_mem_equal(cur->oid, internal_p, obj_len))) {
                /*Concat subject string*/

                /*for example: CN=*/
                libspdm_copy_mem(buffer, buff_len, cur->name, cur->name_len);
                buff_len = (int32_t)(buff_len - cur->name_len);
                buffer += cur->name_len;
                *buffer = '=';
                buff_len--;
                buffer++;

                /*move to string*/
                internal_p += obj_len;
                ret = libspdm_asn1_get_tag(&internal_p, end, &obj_len, cur->default_tag);
                if (!ret) {
                    return false;
                }

                /*for example: AU,*/
                libspdm_copy_mem(buffer, buff_len, internal_p, obj_len);
                buff_len = (int32_t)(buff_len - obj_len);
                buffer += obj_len;
                *buffer = ',';
                buff_len--;
                buffer++;

                if (buff_len < 0) {
                    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"the buffer is too small"));
                    return false;
                }
                break;
            }
        }

        /*can not find the same oid, the subject is wrong*/
        if (cur->name == NULL) {
            return false;
        }
    }

    *buffer = '\0';
    return true;
}

/**
 * Set all attributes object form req_info to CSR
 *
 * @param[in]      req                   CSR to set attributes
 * @param[in]      req_info              requester info to gen CSR
 * @param[in]      req_info_len          The len of requester info
 *
 * @retval  true   Success Set.
 * @retval  false  Set failed.
 **/
bool libspdm_set_attribute_for_req(mbedtls_x509write_csr *req,
                                   uint8_t *req_info, size_t req_info_len,
                                   uint8_t *pub_key_der, size_t pub_key_der_len)
{
    uint8_t *ptr;
    int32_t length;
    size_t obj_len;
    bool ret;
    uint8_t *end;
    uint8_t *ptr_old;

    uint8_t *oid;
    size_t oid_len;
    uint8_t *val;
    size_t val_len;

    uint8_t *pkinfo;
    size_t pkinfo_len;
    uint8_t buffer[LIBSPDM_MAX_SUBJECT_BUFFER_SIZE];

    length = (int32_t)req_info_len;
    ptr = req_info;
    obj_len = 0;
    end = ptr + length;
    ret = false;

    if (req_info == NULL) {
        return false;
    }

    /*req_info sequence, all req_info format is ok because the req_info has been verified before*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);

    /*integer:version*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    /*check req_info version. spec PKCS#10: It shall be 0 for this version of the standard.*/
    if ((obj_len != 1) || (*ptr != 0)) {
        return false;
    }
    ptr += obj_len;

    /*sequence:subject name*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);

    /**/
    libspdm_zero_mem(buffer, sizeof(buffer));
    ret = libspdm_convert_subject_to_string(ptr, obj_len, buffer, LIBSPDM_MAX_SUBJECT_BUFFER_SIZE);
    if (!ret) {
        return false;
    }

    /*set subject name*/
    ret = mbedtls_x509write_csr_set_subject_name(req, (const char *)buffer);
    if (ret != 0) {
        return false;
    }

    ptr += obj_len;

    pkinfo = ptr;
    /*sequence:subject pkinfo*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);

    pkinfo_len = obj_len + ptr - pkinfo;
    /*check the public key info*/
    if (!((pkinfo_len == pub_key_der_len) &&
          (libspdm_consttime_is_mem_equal(pub_key_der, pkinfo, pkinfo_len)))) {
        return false;
    }

    ptr += obj_len;

    /*[0]: attributes*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                               LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    /*there is no attributes*/
    if (ptr == end) {
        return true;
    }

    /*there is some attributes object: 1,2 ...*/
    while (ret)
    {
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE |
                                   LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (ret) {
            /*save old position*/
            ptr_old = ptr;

            /*move to the next sequence*/
            ptr += obj_len;

            /*get attributes oid*/
            ret = libspdm_asn1_get_tag(&ptr_old, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
            if (!ret) {
                return false;
            }
            oid = ptr_old;
            oid_len = obj_len;

            ptr_old += obj_len;
            /*get attributes val*/
            ret = libspdm_asn1_get_tag(&ptr_old, end, &obj_len,
                                       LIBSPDM_CRYPTO_ASN1_SET |
                                       LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
            if (!ret) {
                return false;
            }
            ret = libspdm_asn1_get_tag(&ptr_old, end, &obj_len, LIBSPDM_CRYPTO_ASN1_UTF8_STRING);
            if (!ret) {
                return false;
            }
            val = ptr_old;
            val_len = obj_len;

            /*set attributes*/
            ret = mbedtls_x509write_csr_set_extension(req, (const char *)oid, oid_len, 0, val,
                                                      val_len);

            if (ret) {
                return false;
            }

        } else {
            break;
        }
    }

    if (ptr == end) {
        return true;
    } else {
        return false;
    }
}

/**
 * Gen CSR
 *
 * @param[in]      hash_nid              hash algo for sign
 * @param[in]      asym_nid              asym algo for sign
 *
 * @param[in]      requester_info        requester info to gen CSR
 * @param[in]      requester_info_length The len of requester info
 *
 * @param[in]       is_ca                if true, set basic_constraints: CA:true; Otherwise, set to false.
 *
 * @param[in]      context               Pointer to asymmetric context
 * @param[in]      subject_name          Subject name: should be break with ',' in the middle
 *                                       example: "C=AA,CN=BB"
 * Subject names should contain a comma-separated list of OID types and values:
 * The valid OID type name is in:
 * {"CN", "commonName", "C", "countryName", "O", "organizationName","L",
 * "OU", "organizationalUnitName", "ST", "stateOrProvinceName", "emailAddress",
 * "serialNumber", "postalAddress", "postalCode", "dnQualifier", "title",
 * "SN","givenName","GN", "initials", "pseudonym", "generationQualifier", "domainComponent", "DC"}.
 * Note: The object of C and countryName should be CSR Supported Country Codes
 *
 * @param[in, out]      csr_len               For input, csr_len is the size of store CSR buffer.
 *                                            For output, csr_len is CSR len for DER format
 * @param[in, out]      csr_pointer           For input, csr_pointer is buffer address to store CSR.
 *                                            For output, csr_pointer is address for stored CSR.
 *                                            The csr_pointer address will be changed.
 * @param[in]           base_cert             An optional leaf certificate whose
 *                                            extensions should be copied to the CSR
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen CSR.
 **/
bool libspdm_gen_x509_csr(size_t hash_nid, size_t asym_nid,
                          uint8_t *requester_info, size_t requester_info_length,
                          bool is_ca,
                          void *context, char *subject_name,
                          size_t *csr_len, uint8_t *csr_pointer,
                          void *base_cert)
{
    int ret;
    bool result;
    size_t csr_buffer_size;

    mbedtls_x509write_csr req;
    mbedtls_md_type_t md_alg;
    mbedtls_asn1_sequence extns;
    mbedtls_asn1_sequence *next_oid;
    mbedtls_x509_buf buf;
    mbedtls_x509_crt *cert;
    mbedtls_pk_context key;

    uint8_t pubkey_buffer[LIBSPDM_MAX_PUBKEY_DER_BUFFER_SIZE];
    uint8_t *pubkey_der_data;
    size_t pubkey_der_len;
    size_t oid_tag_len;

    /*basic_constraints: CA: false */
    #define BASIC_CONSTRAINTS_STRING_FALSE {0x30, 0x00}
    uint8_t basic_constraints_false[] = BASIC_CONSTRAINTS_STRING_FALSE;

    /*basic_constraints: CA: true */
    #define BASIC_CONSTRAINTS_STRING_TRUE {0x30, 0x03, 0x01, 0x01, 0xFF}
    uint8_t basic_constraints_true[] = BASIC_CONSTRAINTS_STRING_TRUE;

    /* Init */
    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_init(&key);
    csr_buffer_size = *csr_len;
    next_oid = NULL;

    ret = 1;
    switch (asym_nid)
    {
    case LIBSPDM_CRYPTO_NID_RSASSA2048:
    case LIBSPDM_CRYPTO_NID_RSAPSS2048:
    case LIBSPDM_CRYPTO_NID_RSASSA3072:
    case LIBSPDM_CRYPTO_NID_RSAPSS3072:
    case LIBSPDM_CRYPTO_NID_RSASSA4096:
    case LIBSPDM_CRYPTO_NID_RSAPSS4096:
        ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (ret != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"failed\n ! mbedtls_pk_setup %d", ret));
            goto free_all;
        }
        ret = mbedtls_rsa_copy(mbedtls_pk_rsa(key), (mbedtls_rsa_context *)context);
        if (ret != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"failed\n ! mbedtls_rsa_copy %d", ret));
            goto free_all;
        }
        ret = mbedtls_rsa_complete(mbedtls_pk_rsa(key));
        if (ret != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"failed\n ! mbedtls_rsa_complete %d", ret));
            goto free_all;
        }
        break;
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521:
        ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"failed\n ! mbedtls_pk_setup %d", ret));
            goto free_all;
        }
        /*mbedtls_ecdh_context include mbedtls_ecdsa_context,can be treated as mbedtls_ecdsa_context*/
        ret = mbedtls_ecdsa_from_keypair(mbedtls_pk_ec(key), (mbedtls_ecdsa_context *)context);
        if (ret != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"failed\n ! mbedtls_ecdsa_from_keypair %d", ret));
            goto free_all;
        }
        break;
    default:
        return false;
    }

    switch (hash_nid)
    {
    case LIBSPDM_CRYPTO_NID_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        break;
    case LIBSPDM_CRYPTO_NID_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        break;
    case LIBSPDM_CRYPTO_NID_SHA512:
        md_alg = MBEDTLS_MD_SHA512;
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_256:
        md_alg = MBEDTLS_MD_SHA3_256;
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_384:
        md_alg = MBEDTLS_MD_SHA3_384;
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_512:
        md_alg = MBEDTLS_MD_SHA3_512;
        break;
    default:
        ret = 1;
        goto free_all;
    }

    /* Set the md alg */
    mbedtls_x509write_csr_set_md_alg(&req, md_alg);

    /* Set the subject name */
    if (subject_name != NULL) {
        ret = mbedtls_x509write_csr_set_subject_name(&req, subject_name);
        if (ret != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "failed\n ! mbedtls_x509write_csr_set_subject_name returned %d", ret));
            goto free_all;
        }
    }

    libspdm_zero_mem(pubkey_buffer, sizeof(pubkey_buffer));
    pubkey_der_len = mbedtls_pk_write_pubkey_der(&key, pubkey_buffer, sizeof(pubkey_buffer));
    if (pubkey_der_len > 0) {
        /*Note: data is written at the end of the buffer!*/
        pubkey_der_data = pubkey_buffer + sizeof(pubkey_buffer) - pubkey_der_len;
    } else {
        goto free_all;
    }

    /* requester info parse
     * check the req_info version and subjectPKInfo;
     * get attribute and subject from req_info and set them to CSR;
     **/
    if (requester_info_length != 0) {
        result = libspdm_set_attribute_for_req(&req, requester_info, requester_info_length,
                                               pubkey_der_data, pubkey_der_len);
        if (!result) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"set_attribute failed !\n"));
            goto free_all;
        }
    }

    /* Set key */
    mbedtls_x509write_csr_set_key(&req, &key);

    /*set basicConstraints*/
    if (mbedtls_x509write_csr_set_extension(&req, MBEDTLS_OID_BASIC_CONSTRAINTS,
                                            MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS),
                                            0,
                                            is_ca ? basic_constraints_true : basic_constraints_false,
                                            is_ca ?
                                            sizeof(basic_constraints_true) :
                                            sizeof(basic_constraints_false)
                                            ) != 0) {
        ret = 1;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "mbedtls_x509write_csr_set_extension set basicConstraints failed \n"));
        goto free_all;
    }

    if (base_cert != NULL) {
        cert = base_cert;
        buf = cert->v3_ext;
        if (mbedtls_asn1_get_sequence_of(&buf.p, buf.p + buf.len, &extns,
                                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
            ret = 1;
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "mbedtls_x509write_csr_set_extension unable to get sequence\n"));
            goto free_all;
        }

        next_oid = &extns;
    }

    while (next_oid) {
        if (mbedtls_asn1_get_tag(&(next_oid->buf.p), next_oid->buf.p + next_oid->buf.len,
                                 &oid_tag_len, MBEDTLS_ASN1_OID)) {
            ret = 1;
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "mbedtls_x509write_csr_set_extension unable to get OID tag\n"));
            goto free_all;
        }

        if (MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_BASIC_CONSTRAINTS, next_oid->buf.p, oid_tag_len) == 0) {
            next_oid = next_oid->next;
            continue;
        }

        if (MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER, next_oid->buf.p,
                                oid_tag_len) == 0) {
            next_oid = next_oid->next;
            continue;
        }

        if (mbedtls_x509write_csr_set_extension(&req, (const char *)next_oid->buf.p,
                                                oid_tag_len, 0,
                                                next_oid->buf.p + oid_tag_len,
                                                next_oid->buf.len - oid_tag_len
                                                ) != 0) {
            ret = 1;
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "mbedtls_x509write_csr_set_extension set custom OID failed \n"));
            goto free_all;
        }

        next_oid = next_oid->next;
    }

    /*csr data is written at the end of the buffer*/
    ret = mbedtls_x509write_csr_der(&req, csr_pointer, csr_buffer_size, libspdm_myrand, NULL);
    if (ret <= 0) {
        ret = 1;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"mbedtls_x509write_csr_der failed \n"));
        goto free_all;
    }

    *csr_len = (size_t)ret;
    /*make csr_pointer store csr data*/
    memmove(csr_pointer, csr_pointer + csr_buffer_size - *csr_len, *csr_len);

    ret = 0;
free_all:
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&key);

    return(ret == 0);
}

bool libspdm_gen_x509_csr_with_pqc(
    size_t hash_nid, size_t asym_nid, size_t pqc_asym_nid,
    uint8_t *requester_info, size_t requester_info_length,
    bool is_ca,
    void *context, char *subject_name,
    size_t *csr_len, uint8_t *csr_pointer,
    void *base_cert)
{
    if (pqc_asym_nid != 0) {
        return false;
    }
    return libspdm_gen_x509_csr(hash_nid, asym_nid, requester_info,
                                requester_info_length, is_ca, context,
                                subject_name, csr_len, csr_pointer, base_cert);
}

#endif
