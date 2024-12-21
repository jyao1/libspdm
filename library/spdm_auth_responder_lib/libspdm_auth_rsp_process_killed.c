/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

libspdm_return_t libspdm_auth_get_response_process_killed(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_kill_auth_process_request_t *spdm_auth_request;
    spdm_auth_process_killed_response_t *spdm_auth_response;
    spdm_auth_auth_proc_id_t auth_proc_id;
    libspdm_session_info_t *session_info;
    uint16_t session_credential_id;
    uint16_t credential_privileges;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_KILL_AUTH_PROCESS);

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

    if ((session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) ||
        (!has_auth)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
            response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_auth_kill_auth_process_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
    credential_privileges = libspdm_auth_device_get_credential_privileges(
        spdm_context, session_id, session_credential_id);
    if ((credential_privileges &
        SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_KILL_AUTH_PROC) == 0) {
        return libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
                response_size, response);
    }

    if (spdm_auth_request->credential_id != session_info->auth.common.credential_id) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
            response_size, response);
    }

    libspdm_get_auth_proc_id_from_session (
        spdm_context, session_info, &auth_proc_id
    );
    if (!libspdm_consttime_is_mem_equal(&spdm_auth_request->auth_proc_id,
                                        &auth_proc_id,
                                        sizeof(spdm_auth_auth_proc_id_t)) != 0) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
            response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_process_killed_response_t));
    *response_size = sizeof(spdm_auth_process_killed_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_PROCESS_KILLED;
    libspdm_copy_mem(&spdm_auth_response->auth_proc_id,
                     sizeof(spdm_auth_response->auth_proc_id),
                     &spdm_auth_request->auth_proc_id,
                     sizeof(spdm_auth_request->auth_proc_id));

    /* -=[Update State Phase]=- */
    session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_END;

    return LIBSPDM_STATUS_SUCCESS;
}
