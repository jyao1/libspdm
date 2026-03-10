/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_auth_version_number_t version_number_entry[SPDM_AUTH_MAX_VERSION_COUNT];
} libspdm_auth_auth_version_response_max_t;
#pragma pack()

libspdm_return_t libspdm_auth_get_auth_version(
    void *context, uint32_t session_id,
    uint8_t *version_number_entry_count,
    spdm_auth_version_number_t *version_number_entry)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    bool result;
    spdm_auth_get_auth_version_request_t spdm_auth_request;
    size_t spdm_auth_request_size;
    libspdm_auth_auth_version_response_max_t spdm_auth_response;
    spdm_auth_error_response_t *spdm_auth_error;
    size_t spdm_auth_response_size;
    spdm_auth_version_number_t common_auth_version;

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
    spdm_auth_request.header.request_response_code = SPDM_AUTH_GET_AUTH_VERSION;
    spdm_auth_request_size = sizeof(spdm_auth_get_auth_version_request_t);

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
    } else if (spdm_auth_response.header.request_response_code != SPDM_AUTH_AUTH_VERSION) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_auth_version_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_auth_response.version_number_entry_count > SPDM_AUTH_MAX_VERSION_COUNT) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response.version_number_entry_count == 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_auth_version_response_t) +
        spdm_auth_response.version_number_entry_count * sizeof(spdm_auth_version_number_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    spdm_auth_response_size = sizeof(spdm_version_response_t) +
                              spdm_auth_response.version_number_entry_count * sizeof(spdm_auth_version_number_t);

    result = libspdm_negotiate_connection_version (
        &common_auth_version,
        spdm_context->local_context.auth.version.auth_version,
        spdm_context->local_context.auth.version.auth_version_count,
        spdm_auth_response.version_number_entry,
        spdm_auth_response.version_number_entry_count);
    if (!result) {
        status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
        goto receive_done;
    }

    session_info->auth.auth_version = common_auth_version;

    if (version_number_entry_count != NULL && version_number_entry != NULL) {
        if (*version_number_entry_count < spdm_auth_response.version_number_entry_count) {
            *version_number_entry_count = spdm_auth_response.version_number_entry_count;
            status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            goto receive_done;
        } else {
            *version_number_entry_count = spdm_auth_response.version_number_entry_count;
            libspdm_copy_mem(version_number_entry,
                             spdm_auth_response.version_number_entry_count *
                             sizeof(spdm_version_number_t),
                             spdm_auth_response.version_number_entry,
                             spdm_auth_response.version_number_entry_count *
                             sizeof(spdm_version_number_t));
            libspdm_version_number_sort (version_number_entry, *version_number_entry_count);
        }
    }

    /* -=[Update State Phase]=- */
    if (session_info->auth.auth_session_state < LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_VERSION) {
        session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_AFTER_GET_VERSION;
    }
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    return status;
}
