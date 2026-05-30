/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Key context wrapper structure definition for AWS-LC.
 * Unified context structure for EC, RSA, EdDSA, DH, ML-DSA, and ML-KEM keys.
 * Also includes HMAC context wrapper structure.
 **/

#ifndef __KEY_CONTEXT_H__
#define __KEY_CONTEXT_H__

#include <openssl/evp.h>
#include <openssl/hmac.h>

/**
 * Unified key context wrapper structure
 * Wraps EVP_PKEY to provide a clean interface and future extensibility
 * Supports EC, RSA, EdDSA, DH, ML-DSA, and ML-KEM keys
 */
typedef struct {
    EVP_PKEY *evp_pkey;
} libspdm_key_context;

/**
 * HMAC context wrapper structure
 * Wraps HMAC_CTX for HMAC operations (AWS-LC uses OpenSSL 1.1 style API)
 */
typedef struct {
    HMAC_CTX *hmac_ctx;
} libspdm_mac_context;

#endif /* __KEY_CONTEXT_H__ */
