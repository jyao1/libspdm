/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

libspdm_return_t libspdm_auth_get_response_auth_policy(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_get_auth_policy_request_t *spdm_auth_request;
    spdm_auth_auth_policy_response_t *spdm_auth_response;
    uint16_t policy_attributes;
    uint8_t policy_list[sizeof(spdm_auth_policy_list_t) +
                        LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT *
                        sizeof(spdm_auth_policy_struct_for_dsp0289_t)];
    spdm_auth_policy_list_t *policy_list_ptr;
    libspdm_session_info_t *session_info;
    bool ret;
    uint8_t device_state;
    bool operation_failed;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_GET_AUTH_POLICY);

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

    device_state = libspdm_auth_device_get_device_provisioning_state(spdm_context, session_id);
    if ((device_state != SPDM_AUTH_DEVICE_PROVISION_STATE_DEFAULT_STATE) &&
        ((session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) ||
         (!has_auth))) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
            response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_auth_get_auth_policy_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    operation_failed = false;
    ret = libspdm_auth_device_get_auth_policy (
        spdm_context, session_id, has_auth,
        spdm_auth_request->credential_id,
        &policy_attributes,
        sizeof(policy_list),
        &policy_list,
        &operation_failed);
    if (!ret) {
        if (operation_failed) {
            return libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_OPERATION_FAILED,
                response_size, response);
        } else {
            return libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                response_size, response);
        }
    }
    policy_list_ptr = (void *)&policy_list;

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_auth_policy_response_t) +
                                     policy_list_ptr->num_of_policies *
                                     sizeof(spdm_auth_policy_struct_for_dsp0289_t));
    *response_size = sizeof(spdm_auth_auth_policy_response_t) +
                     policy_list_ptr->num_of_policies *
                     sizeof(spdm_auth_policy_struct_for_dsp0289_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_AUTH_POLICY;
    spdm_auth_response->policy_attributes = policy_attributes;
    libspdm_copy_mem(&spdm_auth_response->policy_list,
                     sizeof(spdm_auth_policy_list_t) +
                     policy_list_ptr->num_of_policies *
                     sizeof(spdm_auth_policy_struct_for_dsp0289_t),
                     &policy_list,
                     sizeof(spdm_auth_policy_list_t) +
                     policy_list_ptr->num_of_policies *
                     sizeof(spdm_auth_policy_struct_for_dsp0289_t));

    return LIBSPDM_STATUS_SUCCESS;
}
