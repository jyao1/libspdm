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

typedef struct {
    spdm_auth_credential_struct_t cred_params;
    uint8_t credential_data[LIBSPDM_AUTH_MAX_CREDENTIAL_DATA_SIZE];
} libspdm_sample_cred_params_data_t;

libspdm_sample_cred_params_data_t m_cred_params_data[SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT];
size_t m_cred_params_data_size[SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT];
uint16_t m_credential_attributes[SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT];
bool m_cred_params_data_initialized;

bool libspdm_auth_device_reset_cred_id_params(
    void *spdm_context, uint32_t session_id, bool reset_locked, uint16_t credential_id)
{
    size_t index;
    uint32_t base_asym_algo;
    void *key_data;
    size_t key_data_size;
    bool result;
    uint16_t credential_privileges;
    uint16_t session_credential_id;

    index = credential_id;
    if (index >= LIBSPDM_ARRAY_SIZE(m_cred_params_data)) {
        return false;
    }
    if (!reset_locked) {
        if ((m_credential_attributes[index] & SPDM_AUTH_CRED_ATTRIBUTES_LOCKED) != 0) {
            return false;
        }
        session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
        credential_privileges = libspdm_auth_device_get_credential_privileges(
            spdm_context, session_id, session_credential_id);
        if ((credential_privileges &
            SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_RESET_TO_DEFAULTS) == 0) {
            return false;
        }
    }

    m_cred_params_data[index].cred_params.credential_id = (uint16_t)index;
    m_cred_params_data[index].cred_params.credential_type =
        SPDM_AUTH_CREDENTIAL_TYPE_ASYMMETRIC_KEY;
    m_cred_params_data[index].cred_params.auth_base_algo =
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072;
    m_cred_params_data[index].cred_params.auth_base_hash_algo =
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_384;

    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(
        m_cred_params_data[index].cred_params.auth_base_algo);
    result = libspdm_read_requester_public_key((uint16_t)base_asym_algo, &key_data, &key_data_size);
    if (!result) {
        return false;
    }
    if (key_data_size > sizeof(m_cred_params_data[index].credential_data)) {
        LIBSPDM_ASSERT(false);
        return false;
    }

    m_cred_params_data[index].cred_params.credential_data_size = (uint32_t)key_data_size;
    libspdm_copy_mem(m_cred_params_data[index].credential_data,
                     sizeof(m_cred_params_data[index].credential_data),
                     key_data,
                     key_data_size);

    m_cred_params_data_size[index] =
        sizeof(m_cred_params_data[index].cred_params) +
        m_cred_params_data[index].cred_params.credential_data_size;

    m_credential_attributes[index] = SPDM_AUTH_CRED_ATTRIBUTES_LOCKABLE |
                                     SPDM_AUTH_CRED_ATTRIBUTES_UNLOCKABLE;

    return true;
}

void libspdm_auth_device_init_cred_id_params_all(void *spdm_context, uint32_t session_id, bool reset_locked)
{
    size_t index;

    for (index = 0; index < SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT; index++) {
        libspdm_auth_device_reset_cred_id_params (spdm_context, session_id, reset_locked, (uint16_t)index);
    }

    m_cred_params_data_initialized = true;
}

size_t libspdm_auth_device_get_cred_params_index_from_credential_id (uint32_t credential_id)
{
    size_t index;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_cred_params_data); index++) {
        if (m_cred_params_data[index].cred_params.credential_id == credential_id) {
            return index;
        }
    }
    return LIBSPDM_AUTH_DEVICE_INVALID_INDEX;
}

uint64_t libspdm_auth_device_get_auth_base_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_cred_params_data_initialized) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_cred_params_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_cred_params_data[index].cred_params.auth_base_algo;
}

uint64_t libspdm_auth_device_get_auth_base_hash_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_cred_params_data_initialized) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_cred_params_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_cred_params_data[index].cred_params.auth_base_hash_algo;
}

uint16_t libspdm_auth_device_get_credential_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_cred_params_data_initialized) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_cred_params_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_credential_attributes[index];
}

bool libspdm_auth_device_lock_credential_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;
    uint16_t credential_privileges;
    uint16_t session_credential_id;

    index = libspdm_auth_device_get_cred_params_index_from_credential_id(
        credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    if ((m_credential_attributes[index] & SPDM_AUTH_CRED_ATTRIBUTES_LOCKABLE) == 0) {
        return false;
    }
    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
    if (session_credential_id != credential_id) {
        return false;
    }
    credential_privileges = libspdm_auth_device_get_credential_privileges(
        spdm_context, session_id, session_credential_id);
    if ((credential_privileges &
         SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_LOCK_SELF) == 0) {
        return false;
    }
    m_credential_attributes[index] |= SPDM_AUTH_CRED_ATTRIBUTES_LOCKED;
    return true;
}

bool libspdm_auth_device_unlock_credential_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;
    uint16_t credential_privileges;
    uint16_t session_credential_id;

    index = libspdm_auth_device_get_cred_params_index_from_credential_id(
        credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    if ((m_credential_attributes[index] & SPDM_AUTH_CRED_ATTRIBUTES_UNLOCKABLE) == 0) {
        return false;
    }
    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
    if (session_credential_id != credential_id) {
        return false;
    }
    credential_privileges = libspdm_auth_device_get_credential_privileges(
        spdm_context, session_id, session_credential_id);
    if ((credential_privileges &
         SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_LOCK_SELF) == 0) {
        return false;
    }
    m_credential_attributes[index] &= ~SPDM_AUTH_CRED_ATTRIBUTES_LOCKED;
    return true;
}

bool libspdm_auth_device_get_algo_from_credential_id(
    void *spdm_context,
    uint32_t session_id,
    uint16_t credential_id,
    uint64_t *auth_base_algo,
    uint64_t *auth_base_hash_algo
    )
{
    size_t index;

    if (!m_cred_params_data_initialized) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_cred_params_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    if (credential_id != m_cred_params_data[index].cred_params.credential_id) {
        return false;
    }
    *auth_base_algo = m_cred_params_data[index].cred_params.auth_base_algo;
    *auth_base_hash_algo = m_cred_params_data[index].cred_params.auth_base_hash_algo;
    return true;
}

bool libspdm_auth_device_set_cred_id_params(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint8_t set_cred_info_op,
    size_t cred_params_size,
    const void *cred_params,
    bool *operation_failed
    )
{
    const spdm_auth_credential_struct_t *cred_params_data;
    uint16_t message_caps;
    size_t index;
    uint64_t allowed_auth_base_asym_algo;
    uint64_t allowed_auth_base_hash_algo;
    uint16_t credential_privileges;
    uint16_t session_credential_id;

    if (!m_cred_params_data_initialized) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, true);
    }
    *operation_failed = false;

    cred_params_data = cred_params;
    index = libspdm_auth_device_get_cred_params_index_from_credential_id(
        cred_params_data->credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);

    *operation_failed = true;
    switch (set_cred_info_op) {
    case SPDM_AUTH_SET_CRED_INFO_OP_PARAMETER_CHANGE:
        if (cred_params_size > sizeof(m_cred_params_data[index])) {
            return false;
        }
        message_caps = libspdm_auth_device_get_message_caps(spdm_context, session_id);
        if ((message_caps & SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_CRED_ID_PARAMS_CAP) == 0) {
            return false;
        }
        if ((m_credential_attributes[index] & SPDM_AUTH_CRED_ATTRIBUTES_LOCKED) != 0) {
            return false;
        }
        if (cred_params_data->credential_type != 
             m_cred_params_data[index].cred_params.credential_type) {
            return false;
        }
        allowed_auth_base_asym_algo = libspdm_auth_device_get_allowed_auth_base_asym_algo(
            spdm_context, session_id, cred_params_data->credential_id);
        if ((cred_params_data->auth_base_algo |
             allowed_auth_base_asym_algo) != allowed_auth_base_asym_algo) {
            return false;
        }
        allowed_auth_base_hash_algo = libspdm_auth_device_get_allowed_auth_base_hash_algo(
            spdm_context, session_id, cred_params_data->credential_id);
        if ((cred_params_data->auth_base_hash_algo |
             allowed_auth_base_hash_algo) != allowed_auth_base_hash_algo) {
            return false;
        }
        if (session_credential_id != cred_params_data->credential_id) {
            credential_privileges = libspdm_auth_device_get_credential_privileges(
                spdm_context, session_id, session_credential_id);
            if ((credential_privileges &
                SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_MODIFY_CREDENTIAL_INFO) == 0) {
                return false;
            }
        }

        m_cred_params_data[index].cred_params.auth_base_algo =
            cred_params_data->auth_base_algo;
        m_cred_params_data[index].cred_params.auth_base_hash_algo =
            cred_params_data->auth_base_hash_algo;
        m_cred_params_data[index].cred_params.credential_data_size =
            cred_params_data->credential_data_size;
        libspdm_copy_mem(m_cred_params_data[index].credential_data,
                         sizeof(m_cred_params_data[index].credential_data),
                         cred_params_data + 1,
                         cred_params_data->credential_data_size);
        m_cred_params_data_size[index] =
            sizeof(m_cred_params_data[index].cred_params) +
            m_cred_params_data[index].cred_params.credential_data_size;
        return true;
    case SPDM_AUTH_SET_CRED_INFO_OP_LOCK:
        if (!has_auth) {
            return false;
        }
        return libspdm_auth_device_lock_credential_attributes (
            spdm_context, session_id, cred_params_data->credential_id);
    case SPDM_AUTH_SET_CRED_INFO_OP_UNLOCK:
        if (!has_auth) {
            return false;
        }
        return libspdm_auth_device_unlock_credential_attributes (
            spdm_context, session_id, cred_params_data->credential_id);
    default:
        *operation_failed = false;
        return false;
    }
}

bool libspdm_auth_device_get_cred_id_params(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint16_t credential_id,
    uint16_t *cred_attributes,
    size_t cred_params_size,
    void *cred_params,
    bool *operation_failed
    )
{
    size_t index;
    uint16_t credential_privileges;
    uint16_t session_credential_id;

    if (!m_cred_params_data_initialized) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, true);
    }
    *operation_failed = false;

    index = libspdm_auth_device_get_cred_params_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    *operation_failed = true;
    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
    if (session_credential_id != credential_id) {
        credential_privileges = libspdm_auth_device_get_credential_privileges(
            spdm_context, session_id, session_credential_id);
        if ((credential_privileges &
            SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_QUERY_CREDENTIAL_INFO) == 0) {
            return false;
        }
    }

    *operation_failed = false;
    *cred_attributes = m_credential_attributes[index];
    if (cred_params_size < m_cred_params_data_size[index]) {
        return false;
    }
    libspdm_copy_mem(cred_params,
                     cred_params_size,
                     &m_cred_params_data[index],
                     m_cred_params_data_size[index]);
    return true;
}

bool libspdm_auth_device_reset_to_default_cred_id_params(
    void *spdm_context,
    uint32_t session_id,
    bool reset_locked,
    uint16_t credential_id,
    uint16_t sv_reset_data_type_count,
    size_t sv_reset_data_type_list_size,
    const void *sv_reset_data_type_list
    )
{
    if (credential_id == SPDM_AUTH_CREDENTIAL_ID_ALL) {
        libspdm_auth_device_init_cred_id_params_all (spdm_context, session_id, reset_locked);
        return true;
    } else {
        return libspdm_auth_device_reset_cred_id_params (spdm_context, session_id, reset_locked, credential_id);
    }
}
