/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

libspdm_return_t libspdm_auth_get_response_auth_defaults_applied(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_auth_reset_to_default_request_t *spdm_auth_request;
    spdm_auth_auth_defaults_applied_response_t *spdm_auth_response;
    libspdm_session_info_t *session_info;
    bool ret;
    bool reset_required;
    size_t index;
    uint8_t device_state;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_AUTH_RESET_TO_DEFAULT);

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
    if (request_size < sizeof(spdm_auth_auth_reset_to_default_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    reset_required = false;
    ret = libspdm_auth_device_reset_to_default(
        spdm_context, session_id,
        spdm_auth_request->data_type,
        spdm_auth_request->credential_id,
        spdm_auth_request->sv_reset_data_type_count,
        request_size - sizeof(spdm_auth_auth_reset_to_default_request_t),
        spdm_auth_request + 1,
        &reset_required
        );
    if (!ret) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((spdm_auth_request->credential_id != 0xFFFF) &&
            (spdm_auth_request->credential_id !=
             spdm_context->session_info[index].auth.common.credential_id)) {
            continue;
        }

        if (spdm_context->session_info[index].auth.auth_session_state ==
            LIBSPDM_AUTH_SESSION_STATE_START) {
            spdm_context->session_info[index].auth.auth_session_state =
                LIBSPDM_AUTH_SESSION_STATE_END;
            libspdm_zero_mem(&session_info->auth.common, sizeof(session_info->auth.common));
            if (spdm_context->session_info[index].auth.auth_session_process_type ==
                LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP) {
                libspdm_zero_mem(&session_info->auth.usap, sizeof(session_info->auth.usap));
            }
        }
    }

    if (reset_required) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_RESET_REQUIRED,
            response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_auth_defaults_applied_response_t));
    *response_size = sizeof(spdm_auth_auth_defaults_applied_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_AUTH_DEFAULTS_APPLIED;

    return LIBSPDM_STATUS_SUCCESS;
}
