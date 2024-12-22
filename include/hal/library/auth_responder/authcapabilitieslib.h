/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_RESPONDER_AUTH_CAPABILITIES_LIB_H
#define AUTH_RESPONDER_AUTH_CAPABILITIES_LIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_authorization.h"

extern uint16_t libspdm_auth_device_get_message_caps(
    void *spdm_context, uint32_t session_id);

extern uint16_t libspdm_auth_device_get_auth_process_caps(
    void *spdm_context, uint32_t session_id);

extern uint8_t libspdm_auth_device_get_device_provisioning_state(
    void *spdm_context, uint32_t session_id);

extern uint8_t libspdm_auth_device_get_auth_record_process_time(
    void *spdm_context, uint32_t session_id);

extern uint64_t libspdm_auth_device_get_auth_base_asym_algo_supported(
    void *spdm_context, uint32_t session_id);

extern uint64_t libspdm_auth_device_get_auth_base_hash_algo_supported(
    void *spdm_context, uint32_t session_id);

extern bool libspdm_auth_device_get_supported_policy_owner_id_list(
    void *spdm_context,
    uint32_t session_id,
    uint16_t *supported_policy_owner_id_count,
    size_t *supported_policy_owner_id_list_size,
    void *supported_policy_owner_id_list
    );

#endif /* AUTH_RESPONDER_AUTH_CAPABILITIES_LIB_H */
