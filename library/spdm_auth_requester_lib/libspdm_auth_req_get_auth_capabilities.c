/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t message_caps;
    uint16_t auth_process_caps;
    uint8_t device_provisioning_state;
    uint8_t auth_record_process_time;
    uint64_t auth_base_asym_algo_supported;
    uint64_t auth_base_hash_algo_supported;
    uint16_t supported_policy_owner_id_count;
    spdm_svh_dmtf_dsp_header_t
        supported_policy_owner_id_list[LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT];
} libspdm_auth_auth_capabilities_response_max_t;
#pragma pack()

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
    )
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    spdm_auth_get_auth_capabilities_request_t spdm_auth_request;
    size_t spdm_auth_request_size;
    libspdm_auth_auth_capabilities_response_max_t spdm_auth_response;
    spdm_auth_error_response_t *spdm_auth_error;
    size_t spdm_auth_response_size;
    size_t supported_policy_owner_id_size;

    spdm_context = context;
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (session_info->auth.auth_session_process_type == LIBSPDM_AUTH_SESSION_PROCESS_TYPE_NONE) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    /* -=[Construct Request Phase]=- */
    libspdm_zero_mem(&spdm_auth_request, sizeof(spdm_auth_request));
    spdm_auth_request.header.request_response_code = SPDM_AUTH_GET_AUTH_CAPABILITIES;
    spdm_auth_request_size = sizeof(spdm_auth_get_auth_capabilities_request_t);

    /* -=[Send Receive Phase]=- */
    spdm_auth_response_size = sizeof(spdm_auth_response);
    status = libspdm_auth_send_receive (spdm_context, session_id, false,
                                        spdm_auth_request_size,
                                        (const uint8_t *)&spdm_auth_request,
                                        &spdm_auth_response_size,
                                        &spdm_auth_response
                                        );
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_auth_response_size < sizeof(spdm_auth_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_auth_response.header.request_response_code == SPDM_AUTH_ERROR) {
        if (spdm_auth_response_size < sizeof(spdm_auth_error_response_t)) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }
        spdm_auth_error = (void *)&spdm_auth_response;
        status = libspdm_auth_handle_simple_error_response(spdm_context, spdm_auth_error->error_code);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_auth_response.header.request_response_code != SPDM_AUTH_AUTH_CAPABILITIES) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_auth_version_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_auth_response.supported_policy_owner_id_count > LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    supported_policy_owner_id_size = spdm_auth_response_size - sizeof(spdm_auth_auth_capabilities_response_t);
    if (*supported_policy_owner_id_list_size < supported_policy_owner_id_size) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }
    *supported_policy_owner_id_list_size = supported_policy_owner_id_size;

    *message_caps = spdm_auth_response.message_caps;
    *auth_process_caps = spdm_auth_response.auth_process_caps;
    *device_provisioning_state =
        spdm_auth_response.device_provisioning_state;
    *auth_record_process_time =
        spdm_auth_response.auth_record_process_time;
    *auth_base_asym_algo_supported =
        spdm_auth_response.auth_base_asym_algo_supported;
    *auth_base_hash_algo_supported =
        spdm_auth_response.auth_base_hash_algo_supported;
    *supported_policy_owner_id_count =
        spdm_auth_response.supported_policy_owner_id_count;
    libspdm_copy_mem (supported_policy_owner_id_list,
                      *supported_policy_owner_id_list_size,
                      spdm_auth_response.supported_policy_owner_id_list,
                      supported_policy_owner_id_size
                      );

    /* -=[Update State Phase]=- */
    if (session_info->auth.auth_session_state < LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_CAPABILITIES) {
        session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_CAPABILITIES;
    }
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    return status;
}
