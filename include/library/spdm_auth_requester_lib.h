/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_AUTH_REQUESTER_LIB_H
#define SPDM_AUTH_REQUESTER_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "library/spdm_common_lib.h"

libspdm_return_t libspdm_auth_send_receive(
    void *context,
    uint32_t session_id,
    bool need_auth,
    size_t req_size,
    const void *req_data,
    size_t *rsp_size,
    void *rsp_data);

libspdm_return_t libspdm_auth_get_auth_version(
    void *spdm_context, uint32_t session_id,
    uint8_t *version_number_entry_count,
    spdm_auth_version_number_t *version_number_entry);

libspdm_return_t libspdm_auth_select_auth_version(
    void *spdm_context, uint32_t session_id,
    uint8_t auth_version);

libspdm_return_t libspdm_auth_get_auth_capabilities(
    void *context, uint32_t session_id,
    uint16_t *message_caps,
    uint16_t *auth_process_caps,
    uint8_t *device_provisioning_state,
    uint8_t *auth_record_process_time,
    uint64_t *auth_base_asym_algo_supported,
    uint64_t *auth_base_hash_algo_supported,
    uint16_t *supported_policy_owner_id_count,
    size_t *supported_policy_owner_id_list_size,
    void *supported_policy_owner_id_list
    );

libspdm_return_t libspdm_auth_set_cred_id_params(
    void *context, uint32_t session_id,
    bool need_auth,
    uint8_t set_cred_info_op,
    size_t cred_params_size,
    const void *cred_params);

libspdm_return_t libspdm_auth_get_cred_id_params(
    void *context, uint32_t session_id,
    bool need_auth,
    uint16_t credential_id,
    uint16_t *cred_attributes,
    size_t *cred_params_size,
    void *cred_params);

libspdm_return_t libspdm_auth_set_auth_policy(
    void *context, uint32_t session_id,
    bool need_auth,
    uint8_t set_auth_policy_op,
    size_t policy_list_size,
    const void *policy_list);

libspdm_return_t libspdm_auth_get_auth_policy(
    void *context, uint32_t session_id,
    bool need_auth,
    uint16_t credential_id,
    uint16_t *policy_attributes,
    size_t *policy_list_size,
    void *policy_list);

libspdm_return_t libspdm_auth_start_auth(
    void *context, uint32_t session_id,
    uint16_t credential_id);

libspdm_return_t libspdm_auth_end_auth(
    void *context, uint32_t session_id,
    uint16_t credential_id);

libspdm_return_t libspdm_auth_elevate_privilege(
    void *context, uint32_t session_id);

libspdm_return_t libspdm_auth_end_elevated_privilege(
    void *context, uint32_t session_id);

libspdm_return_t libspdm_auth_take_ownership(
    void *context, uint32_t session_id);

libspdm_return_t libspdm_auth_auth_reset_to_default(
    void *context, uint32_t session_id,
    uint16_t data_type, uint16_t credential_id,
    uint16_t sv_reset_data_type_count, size_t sv_reset_data_type_list_size,
    const void *sv_reset_data_type_list);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_AUTH_REQUESTER_LIB_H */
