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
    spdm_svh_dmtf_dsp_header_t policy_owner_id_list[1];
} libspdm_sample_auth_capabilities_data_t;

libspdm_sample_auth_capabilities_data_t m_auth_capabilities_data;
size_t m_auth_capabilities_data_size;
bool m_auth_capabilities_data_initialized;

uint16_t m_message_caps;
uint16_t m_auth_process_caps;
uint8_t m_device_provisioning_state;
uint8_t m_auth_record_process_time;
uint64_t m_auth_base_asym_algo_supported;
uint64_t m_auth_base_hash_algo_supported;
uint16_t m_supported_policy_count;

void libspdm_auth_device_init_auth_capabilities(void *spdm_context)
{
    m_supported_policy_count = 1;
    m_auth_capabilities_data.policy_owner_id_list[0].header.id = SPDM_REGISTRY_ID_DMTF_DSP;
    m_auth_capabilities_data.policy_owner_id_list[0].header.vendor_id_len = 2;
    m_auth_capabilities_data.policy_owner_id_list[0].vendor_id = 289;

    m_auth_capabilities_data_size = m_supported_policy_count *
                                    sizeof(spdm_svh_dmtf_dsp_header_t);

    m_message_caps =
        SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_CRED_ID_PARAMS_CAP |
        SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_AUTH_POLICY_CAP |
        /* SPDM_AUTH_MESSAGE_SUPPORTED_AUTH_EVENT_CAP |*/
        0;
    m_auth_process_caps =
        SPDM_AUTH_PROCESS_SUPPORTED_USAP_CAP |
        SPDM_AUTH_PROCESS_SUPPORTED_SEAP_CAP |
        0;
    m_device_provisioning_state = SPDM_AUTH_DEVICE_PROVISION_STATE_DEFAULT_STATE;
    m_auth_record_process_time = 10;
    m_auth_base_asym_algo_supported =
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
    m_auth_base_hash_algo_supported =
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
        SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SM3_256 |
        0;

    m_auth_capabilities_data_initialized = true;
}

uint16_t libspdm_auth_device_get_message_caps(
    void *spdm_context, uint32_t session_id)
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    return m_message_caps;
}

uint16_t libspdm_auth_device_get_auth_process_caps(
    void *spdm_context, uint32_t session_id)
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    return m_auth_process_caps;
}

uint8_t libspdm_auth_device_get_device_provisioning_state(
    void *spdm_context, uint32_t session_id)
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    return m_device_provisioning_state;
}

uint8_t libspdm_auth_device_get_auth_record_process_time(
    void *spdm_context, uint32_t session_id)
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    return m_auth_record_process_time;
}

uint64_t libspdm_auth_device_get_auth_base_asym_algo_supported(
    void *spdm_context, uint32_t session_id)
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    return m_auth_base_asym_algo_supported;
}

uint64_t libspdm_auth_device_get_auth_base_hash_algo_supported(
    void *spdm_context, uint32_t session_id)
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    return m_auth_base_hash_algo_supported;
}

bool libspdm_auth_device_get_supported_policy_owner_id_list(
    void *spdm_context,
    uint32_t session_id,
    uint16_t *supported_policy_owner_id_count,
    size_t *supported_policy_owner_id_list_size,
    void *supported_policy_owner_id_list
    )
{
    if (!m_auth_capabilities_data_initialized) {
        libspdm_auth_device_init_auth_capabilities (spdm_context);
    }
    *supported_policy_owner_id_count = m_supported_policy_count;
    if (*supported_policy_owner_id_list_size < m_auth_capabilities_data_size) {
        return false;
    }
    *supported_policy_owner_id_list_size = m_auth_capabilities_data_size;
    libspdm_copy_mem(supported_policy_owner_id_list,
                     *supported_policy_owner_id_list_size,
                     &m_auth_capabilities_data,
                     m_auth_capabilities_data_size);
    return true;
}
