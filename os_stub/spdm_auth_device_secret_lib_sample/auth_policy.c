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
#include "internal/libspdm_common_lib.h"

typedef struct {
    spdm_auth_policy_list_t policy_list_header;
    spdm_auth_policy_struct_for_dsp0289_t policies[1];
} libspdm_sample_auth_policy_data_t;

libspdm_sample_auth_policy_data_t m_auth_policy_data[SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT];
size_t m_auth_policy_data_size[SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT];
bool m_auth_policy_data_initialized;

bool libspdm_auth_device_reset_auth_policy(
    void *spdm_context, uint32_t session_id, bool reset_locked, uint16_t credential_id)
{
    size_t index;
    uint16_t policy_attributes;
    uint16_t session_credential_id;
    uint16_t credential_privileges;

    index = credential_id;
    if (index >= LIBSPDM_ARRAY_SIZE(m_auth_policy_data)) {
        return false;
    }
    if (!reset_locked) {
        policy_attributes = libspdm_auth_device_get_policy_attributes(spdm_context, session_id, credential_id);
        if ((policy_attributes & SPDM_AUTH_CRED_ATTRIBUTES_LOCKED) != 0) {
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

    m_auth_policy_data[index].policy_list_header.credential_id = (uint16_t)index;
    m_auth_policy_data[index].policy_list_header.num_of_policies =
        LIBSPDM_ARRAY_SIZE(m_auth_policy_data[index].policies);
    m_auth_policy_data[index].policies[0].policy_owner_id.header.id = SPDM_REGISTRY_ID_DMTF_DSP;
    m_auth_policy_data[index].policies[0].policy_owner_id.header.vendor_id_len = 2;
    m_auth_policy_data[index].policies[0].policy_owner_id.vendor_id = 289;
    m_auth_policy_data[index].policies[0].policy_len =
        sizeof(m_auth_policy_data[index].policies[0].policy);
    m_auth_policy_data[index].policies[0].policy.policy_type = SPDM_AUTH_POLICY_TYPE_GENERAL_POLICY;
    m_auth_policy_data[index].policies[0].policy.policy_len =
        sizeof(m_auth_policy_data[index].policies[0].policy.policy);
    m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_asym_algo =
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
        SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
        SPDM_AUTH_BASE_ASYM_ALGO_EDDSA_ED25519 |
        SPDM_AUTH_BASE_ASYM_ALGO_EDDSA_ED448 |
        0;
    m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_hash_algo =
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SM3_256 |
        0;
    m_auth_policy_data[index].policies[0].policy.policy.credential_privileges = 
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_MODIFY_CREDENTIAL_INFO |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_QUERY_CREDENTIAL_INFO |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_GRANT_OTHER_POLICY |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_REVOKE_OTHER_POLICY |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_QUERY_POLICY |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_RESET_TO_DEFAULTS |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_LOCK_SELF |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_RETRIEVE_AUTH_PROC_LIST |
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_KILL_AUTH_PROC |
        0;
    m_auth_policy_data[index].policies[0].policy.policy.auth_process_privileges = 
        SPDM_AUTH_POLICY_AUTH_PROCESS_PRIVILEGES_SEAP |
        SPDM_AUTH_POLICY_AUTH_PROCESS_PRIVILEGES_USAP |
        0;

    m_auth_policy_data_size[index] =
        sizeof(spdm_auth_policy_list_t) +
        m_auth_policy_data[index].policy_list_header.num_of_policies *
        sizeof(spdm_auth_policy_struct_for_dsp0289_t);

    return true;
}

void libspdm_auth_device_init_auth_policy_all(void *spdm_context, uint32_t session_id, bool reset_locked)
{
    size_t index;

    for (index = 0; index < SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT; index++) {
        libspdm_auth_device_reset_auth_policy (spdm_context, session_id, reset_locked, (uint16_t)index);
    }

    m_auth_policy_data_initialized = true;
}

size_t libspdm_auth_device_get_policy_index_from_credential_id (uint32_t credential_id)
{
    size_t index;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_auth_policy_data); index++) {
        if (m_auth_policy_data[index].policy_list_header.credential_id == credential_id) {
            return index;
        }
    }
    return LIBSPDM_AUTH_DEVICE_INVALID_INDEX;
}

uint64_t libspdm_auth_device_get_allowed_auth_base_asym_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_auth_policy_data_initialized) {
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_policy_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_asym_algo;
}

uint64_t libspdm_auth_device_get_allowed_auth_base_hash_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_auth_policy_data_initialized) {
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_policy_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_hash_algo;
}

uint16_t libspdm_auth_device_get_credential_privileges(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_auth_policy_data_initialized) {
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_policy_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_auth_policy_data[index].policies[0].policy.policy.credential_privileges;
}

uint8_t libspdm_auth_device_get_auth_process_privileges(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    size_t index;

    if (!m_auth_policy_data_initialized) {
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, true);
    }
    index = libspdm_auth_device_get_policy_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        LIBSPDM_ASSERT(false);
        return 0;
    }
    return m_auth_policy_data[index].policies[0].policy.policy.auth_process_privileges;
}

uint16_t libspdm_auth_device_get_policy_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    return libspdm_auth_device_get_credential_attributes(
        spdm_context, session_id, credential_id);
}

bool libspdm_auth_device_lock_policy_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    return libspdm_auth_device_lock_credential_attributes(
        spdm_context, session_id, credential_id);
}

bool libspdm_auth_device_unlock_policy_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    return libspdm_auth_device_unlock_credential_attributes(
        spdm_context, session_id, credential_id);
}

bool libspdm_auth_device_set_auth_policy(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint8_t set_auth_policy_op,
    size_t policy_list_size,
    const void *policy_list,
    bool *operation_failed
    )
{
    const libspdm_sample_auth_policy_data_t *policy_list_data;
    size_t index;
    uint64_t auth_base_asym_algo_supported;
    uint64_t auth_base_hash_algo_supported;
    uint16_t message_caps;
    uint16_t auth_process_caps;
    uint64_t auth_base_algo;
    uint64_t auth_base_hash_algo;
    uint16_t policy_attributes;
    uint16_t session_credential_id;
    bool require_revoke;
    bool require_grant;
    uint16_t credential_privileges;

    if (!m_auth_policy_data_initialized) {
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, true);
    }
    *operation_failed = false;

    policy_list_data = policy_list;
    index = libspdm_auth_device_get_policy_index_from_credential_id(
        policy_list_data->policy_list_header.credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);

    policy_attributes = libspdm_auth_device_get_policy_attributes(
        spdm_context, session_id, policy_list_data->policy_list_header.credential_id);
    *operation_failed = true;
    switch (set_auth_policy_op) {
    case SPDM_AUTH_SET_AUTH_POLICY_OP_POLICY_CHANGE:
        message_caps = libspdm_auth_device_get_message_caps(spdm_context, session_id);
        if ((message_caps & SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_AUTH_POLICY_CAP) == 0) {
            return false;
        }
        if ((policy_attributes & SPDM_AUTH_CRED_ATTRIBUTES_LOCKED) != 0) {
            return false;
        }
        if (policy_list_size != m_auth_policy_data_size[index]) {
            return false;
        }
        if ((policy_list_data->policy_list_header.num_of_policies != 
             m_auth_policy_data[index].policy_list_header.num_of_policies) ||
            (policy_list_data->policies[0].policy_owner_id.header.id != 
             m_auth_policy_data[index].policies[0].policy_owner_id.header.id) ||
            (policy_list_data->policies[0].policy_owner_id.header.vendor_id_len != 
             m_auth_policy_data[index].policies[0].policy_owner_id.header.vendor_id_len) ||
            (policy_list_data->policies[0].policy_owner_id.vendor_id != 
             m_auth_policy_data[index].policies[0].policy_owner_id.vendor_id) ||
            (policy_list_data->policies[0].policy_len != 
             m_auth_policy_data[index].policies[0].policy_len) ||
            (policy_list_data->policies[0].policy.policy_type != 
             m_auth_policy_data[index].policies[0].policy.policy_type) ||
            (policy_list_data->policies[0].policy.policy_len != 
             m_auth_policy_data[index].policies[0].policy.policy_len)
            ) {
            return false;
        }
        auth_base_asym_algo_supported =
            libspdm_auth_device_get_auth_base_asym_algo_supported(spdm_context, session_id);
        if ((policy_list_data->policies[0].policy.policy.allowed_auth_base_asym_algo |
             auth_base_asym_algo_supported) != auth_base_asym_algo_supported) {
            return false;
        }
        auth_base_hash_algo_supported =
            libspdm_auth_device_get_auth_base_hash_algo_supported(spdm_context, session_id);
        if ((policy_list_data->policies[0].policy.policy.allowed_auth_base_hash_algo |
             auth_base_hash_algo_supported) != auth_base_hash_algo_supported) {
            return false;
        }
        auth_process_caps =
            libspdm_auth_device_get_auth_process_caps(spdm_context, session_id);
        if ((policy_list_data->policies[0].policy.policy.auth_process_privileges |
             auth_process_caps) != auth_process_caps) {
            return false;
        }
        if (((policy_list_data->policies[0].policy.policy.credential_privileges &
              SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_MODIFY_CREDENTIAL_INFO) != 0) &&
            ((message_caps & SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_CRED_ID_PARAMS_CAP) == 0)) {
            return false;
        }
        if (((policy_list_data->policies[0].policy.policy.credential_privileges &
              (SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_GRANT_OTHER_POLICY |
               SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_REVOKE_OTHER_POLICY)) != 0) &&
            ((message_caps & SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_AUTH_POLICY_CAP) == 0)) {
            return false;
        }
        auth_base_algo = libspdm_auth_device_get_auth_base_algo(
            spdm_context, session_id,
            policy_list_data->policy_list_header.credential_id);
        if ((policy_list_data->policies[0].policy.policy.allowed_auth_base_asym_algo &
             auth_base_algo) == 0) {
            return false;
        }
        auth_base_hash_algo = libspdm_auth_device_get_auth_base_hash_algo(
            spdm_context, session_id,
            policy_list_data->policy_list_header.credential_id);
        if ((policy_list_data->policies[0].policy.policy.allowed_auth_base_hash_algo &
             auth_base_hash_algo) == 0) {
            return false;
        }
        if (session_credential_id != policy_list_data->policy_list_header.credential_id) {
            require_grant = false;
            require_revoke = false;
            if (m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_asym_algo !=
                policy_list_data->policies[0].policy.policy.allowed_auth_base_asym_algo) {
                require_grant = true;
            }
            if (m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_hash_algo !=
                policy_list_data->policies[0].policy.policy.allowed_auth_base_hash_algo) {
                require_grant = true;
            }
            if ((policy_list_data->policies[0].policy.policy.credential_privileges &
                 m_auth_policy_data[index].policies[0].policy.policy.credential_privileges) !=
                policy_list_data->policies[0].policy.policy.credential_privileges) {
                require_grant = true;
            }
            if ((m_auth_policy_data[index].policies[0].policy.policy.credential_privileges &
                 policy_list_data->policies[0].policy.policy.credential_privileges) !=
                m_auth_policy_data[index].policies[0].policy.policy.credential_privileges) {
                require_revoke = true;
            }
            if ((policy_list_data->policies[0].policy.policy.auth_process_privileges &
                 m_auth_policy_data[index].policies[0].policy.policy.auth_process_privileges) !=
                policy_list_data->policies[0].policy.policy.auth_process_privileges) {
                require_grant = true;
            }
            if ((m_auth_policy_data[index].policies[0].policy.policy.auth_process_privileges &
                 policy_list_data->policies[0].policy.policy.auth_process_privileges) !=
                m_auth_policy_data[index].policies[0].policy.policy.auth_process_privileges) {
                require_revoke = true;
            }

            credential_privileges = libspdm_auth_device_get_credential_privileges(
                spdm_context, session_id, session_credential_id);
            if (require_grant &&
                ((credential_privileges &
                  SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_GRANT_OTHER_POLICY) == 0)) {
                return false;
            }
            if (require_revoke &&
                ((credential_privileges &
                  SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_REVOKE_OTHER_POLICY) == 0)) {
                return false;
            }
        }

        m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_asym_algo =
            policy_list_data->policies[0].policy.policy.allowed_auth_base_asym_algo;
        m_auth_policy_data[index].policies[0].policy.policy.allowed_auth_base_hash_algo =
            policy_list_data->policies[0].policy.policy.allowed_auth_base_hash_algo;
        m_auth_policy_data[index].policies[0].policy.policy.credential_privileges =
            policy_list_data->policies[0].policy.policy.credential_privileges;
        m_auth_policy_data[index].policies[0].policy.policy.auth_process_privileges =
            policy_list_data->policies[0].policy.policy.auth_process_privileges;
        return true;
    case SPDM_AUTH_SET_CRED_INFO_OP_LOCK:
        if (!has_auth) {
            return false;
        }
        return libspdm_auth_device_lock_policy_attributes (
            spdm_context, session_id, policy_list_data->policy_list_header.credential_id);
    case SPDM_AUTH_SET_CRED_INFO_OP_UNLOCK:
        if (!has_auth) {
            return false;
        }
        return libspdm_auth_device_unlock_policy_attributes (
            spdm_context, session_id, policy_list_data->policy_list_header.credential_id);
    default:
        *operation_failed = false;
        return false;
    }
}

bool libspdm_auth_device_get_auth_policy(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint16_t credential_id,
    uint16_t *policy_attributes,
    size_t policy_list_size,
    void *policy_list,
    bool *operation_failed
    )
{
    size_t index;
    uint16_t credential_privileges;
    uint16_t session_credential_id;

    if (!m_auth_policy_data_initialized) {
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, true);
    }
    *operation_failed = false;

    index = libspdm_auth_device_get_policy_index_from_credential_id(credential_id);
    if (index == LIBSPDM_AUTH_DEVICE_INVALID_INDEX) {
        return false;
    }

    *operation_failed = true;
    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
    if (session_credential_id != credential_id) {
        credential_privileges = libspdm_auth_device_get_credential_privileges(
            spdm_context, session_id, credential_id);
        if ((credential_privileges &
            SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_QUERY_POLICY) == 0) {
            return false;
        }
    }

    *operation_failed = false;
    *policy_attributes = libspdm_auth_device_get_policy_attributes(spdm_context, session_id, credential_id);
    if (policy_list_size < m_auth_policy_data_size[index]) {
        return false;
    }
    libspdm_copy_mem(policy_list,
                     policy_list_size,
                     &m_auth_policy_data[index],
                     m_auth_policy_data_size[index]);
    return true;
}

bool libspdm_auth_device_reset_to_default_auth_policy(
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
        libspdm_auth_device_init_auth_policy_all (spdm_context, session_id, reset_locked);
        return true;
    } else {
        return libspdm_auth_device_reset_auth_policy (spdm_context, session_id, reset_locked, credential_id);
    }
}