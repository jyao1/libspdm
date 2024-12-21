/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

#pragma pack(1)
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_auth_version_number_t version_number_entry[SPDM_AUTH_MAX_VERSION_COUNT];
} libspdm_auth_auth_version_response_mine_t;
#pragma pack()

libspdm_return_t libspdm_auth_get_response_auth_version(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_get_auth_version_request_t *spdm_auth_request;
    libspdm_auth_auth_version_response_mine_t *spdm_auth_response;
    libspdm_session_info_t *session_info;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_GET_AUTH_VERSION);

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
    if (request_size < sizeof(spdm_auth_get_auth_version_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(libspdm_auth_auth_version_response_mine_t));
    *response_size =
        sizeof(spdm_auth_auth_version_response_t) +
        spdm_context->local_context.auth.version.auth_version_count *
        sizeof(spdm_auth_version_number_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_AUTH_VERSION;
    spdm_auth_response->version_number_entry_count =
        spdm_context->local_context.auth.version.auth_version_count;
    libspdm_copy_mem(spdm_auth_response->version_number_entry,
                     sizeof(spdm_auth_response->version_number_entry),
                     spdm_context->local_context.auth.version.auth_version,
                     sizeof(spdm_auth_version_number_t) *
                     spdm_context->local_context.auth.version.auth_version_count);

    session_info->auth.auth_version = spdm_context->local_context.auth.version.auth_version
        [spdm_context->local_context.auth.version.auth_version_count - 1];

    /* -=[Update State Phase]=- */
    if (session_info->auth.auth_session_state < LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_VERSION) {
        session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_VERSION;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
