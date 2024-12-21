/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

libspdm_return_t libspdm_auth_get_response_end_auth_rsp(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_end_auth_request_t *spdm_auth_request;
    spdm_auth_end_auth_rsp_response_t *spdm_auth_response;
    libspdm_session_info_t *session_info;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_END_AUTH);

    session_info = libspdm_get_session_info_via_session_id(
        spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_UNSPECIFIED,
            response_size, response);
    }

    if (session_info->auth.auth_session_process_type != LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_UNEXPECTED_REQUEST,
            response_size, response);
    }

    if (session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_UNEXPECTED_REQUEST,
            response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_auth_end_auth_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    if (spdm_auth_request->credential_id != session_info->auth.common.credential_id) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_end_auth_rsp_response_t));
    *response_size = sizeof(spdm_auth_end_auth_rsp_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_END_AUTH_RSP;
    spdm_auth_response->credential_id = spdm_auth_request->credential_id;

    libspdm_zero_mem(&session_info->auth.common, sizeof(session_info->auth.common));
    libspdm_zero_mem(&session_info->auth.usap, sizeof(session_info->auth.usap));

    /* -=[Update State Phase]=- */
    session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_END;

    return LIBSPDM_STATUS_SUCCESS;
}
