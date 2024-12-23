/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_auth_device_secret_lib_internal.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

bool libspdm_auth_device_requester_data_verify(
    void *spdm_context, uint32_t session_id,
    uint16_t credential_id,
    spdm_auth_version_number_t spdm_auth_version,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size)
{
    void *context;
    bool result;
    uint64_t auth_base_algo;
    uint64_t auth_base_hash_algo;
    uint32_t base_asym_algo;
    void *key_data;
    size_t key_data_size;

    result = libspdm_auth_device_get_algo_from_credential_id (
        spdm_context, session_id,
        credential_id, &auth_base_algo, &auth_base_hash_algo);
    if (!result) {
        return false;
    }

    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    result = libspdm_read_requester_public_key((uint16_t)base_asym_algo, &key_data, &key_data_size);
    if (!result) {
        return false;
    }
    result = libspdm_auth_asym_get_public_key_from_der(
        auth_base_algo, key_data, key_data_size, &context);
    if (!result) {
        return false;
    }

    result = libspdm_auth_asym_verify(spdm_auth_version,
                                      auth_base_algo, auth_base_hash_algo, context,
                                      message, message_size,
                                      signature, sig_size);
    libspdm_auth_asym_free(auth_base_algo, context);

    return result;
}
