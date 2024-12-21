/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

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
} libspdm_auth_auth_capabilities_response_mine_t;
#pragma pack()

libspdm_return_t libspdm_auth_get_response_auth_capabilities(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_get_auth_capabilities_request_t *spdm_auth_request;
    libspdm_auth_auth_capabilities_response_mine_t *spdm_auth_response;
    libspdm_session_info_t *session_info;
    bool ret;
    uint16_t supported_policy_owner_id_count;
    size_t supported_policy_owner_id_size;
    spdm_svh_dmtf_dsp_header_t
        supported_policy_owner_id_list[LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT];

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_GET_AUTH_CAPABILITIES);

    session_info = libspdm_get_session_info_via_session_id(
        spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_UNSPECIFIED,
            response_size, response);
    }

    if (session_info->auth.auth_session_process_type == LIBSPDM_AUTH_SESSION_PROCESS_TYPE_NONE) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_UNEXPECTED_REQUEST,
            response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_auth_get_auth_capabilities_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    supported_policy_owner_id_size = sizeof(supported_policy_owner_id_list);
    ret = libspdm_auth_device_get_supported_policy_owner_id_list(
        spdm_context, session_id,
        &supported_policy_owner_id_count,
        &supported_policy_owner_id_size,
        supported_policy_owner_id_list);
    if (!ret) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_auth_capabilities_response_t) +
        supported_policy_owner_id_size);
    *response_size =
        sizeof(spdm_auth_auth_capabilities_response_t) +
        supported_policy_owner_id_size;
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_AUTH_CAPABILITIES;
    spdm_auth_response->message_caps =
        libspdm_auth_device_get_message_caps(spdm_context, session_id);
    spdm_auth_response->auth_process_caps =
        libspdm_auth_device_get_auth_process_caps(spdm_context, session_id);
    spdm_auth_response->auth_record_process_time =
        libspdm_auth_device_get_auth_record_process_time(spdm_context, session_id);
    spdm_auth_response->auth_base_asym_algo_supported =
        libspdm_auth_device_get_auth_base_asym_algo_supported(spdm_context, session_id);
    spdm_auth_response->auth_base_hash_algo_supported =
        libspdm_auth_device_get_auth_base_hash_algo_supported(spdm_context, session_id);
    spdm_auth_response->supported_policy_owner_id_count =
        supported_policy_owner_id_count;
    libspdm_copy_mem(spdm_auth_response->supported_policy_owner_id_list,
                     sizeof(spdm_auth_response->supported_policy_owner_id_list),
                     supported_policy_owner_id_list,
                     supported_policy_owner_id_size);

    /* -=[Update State Phase]=- */
    if (session_info->auth.auth_session_state < LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_CAPABILITIES) {
        session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_CAPABILITIES;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
