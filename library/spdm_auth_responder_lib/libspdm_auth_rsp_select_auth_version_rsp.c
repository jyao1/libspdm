/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

static bool libspdm_auth_check_request_version_compatibility(libspdm_context_t *spdm_context,
                                                             uint8_t version)
{
    uint8_t local_ver;
    size_t index;

    for (index = 0; index < spdm_context->local_context.auth.version.auth_version_count; index++) {
        local_ver = spdm_context->local_context.auth.version.auth_version[index] >>
                    SPDM_AUTH_VERSION_NUMBER_SHIFT_BIT;
        if (local_ver == version) {
            return true;
        }
    }
    return false;
}

libspdm_return_t libspdm_auth_get_response_select_auth_version_rsp(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_select_auth_version_request_t *spdm_auth_request;
    spdm_auth_select_auth_version_rsp_response_t *spdm_auth_response;
    libspdm_session_info_t *session_info;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_SELECT_AUTH_VERSION);

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

    if (session_info->auth.auth_version_selected) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_auth_select_auth_version_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    if (!libspdm_auth_check_request_version_compatibility (
            spdm_context, spdm_auth_request->auth_version)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_VERSION_MISMATCH,
            response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_select_auth_version_rsp_response_t));
    *response_size = sizeof(spdm_auth_select_auth_version_rsp_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_SELECT_AUTH_VERSION_RSP;

    session_info->auth.auth_version = spdm_auth_request->auth_version << SPDM_AUTH_VERSION_NUMBER_SHIFT_BIT;
    session_info->auth.auth_version_selected = true;

    /* -=[Update State Phase]=- */
    if (session_info->auth.auth_session_state < LIBSPDM_AUTH_SESSION_STATE_AFTER_SELECT_VERSION) {
        session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_AFTER_SELECT_VERSION;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
