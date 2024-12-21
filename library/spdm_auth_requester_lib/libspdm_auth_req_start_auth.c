/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

libspdm_return_t libspdm_auth_start_auth(
    void *context, uint32_t session_id,
    uint16_t credential_id)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    spdm_auth_start_auth_request_t spdm_auth_request;
    size_t spdm_auth_request_size;
    spdm_auth_start_auth_rsp_response_t spdm_auth_response;
    spdm_auth_error_response_t *spdm_auth_error;
    size_t spdm_auth_response_size;

    spdm_context = context;
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (session_info->auth.auth_session_process_type != LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (session_info->auth.auth_session_state == LIBSPDM_AUTH_SESSION_STATE_START) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    /* -=[Construct Request Phase]=- */
    libspdm_zero_mem(&spdm_auth_request, sizeof(spdm_auth_request));
    spdm_auth_request.header.request_response_code = SPDM_AUTH_START_AUTH;
    spdm_auth_request.credential_id = credential_id;
    spdm_auth_request.nonce_len = SPDM_AUTH_NONCE_SIZE;
    if(!libspdm_get_random_number(SPDM_AUTH_NONCE_SIZE, spdm_auth_request.nonce)) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    spdm_auth_request_size = sizeof(spdm_auth_start_auth_request_t);

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
    } else if (spdm_auth_response.header.request_response_code != SPDM_AUTH_START_AUTH_RSP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_start_auth_rsp_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_auth_response.credential_id != spdm_auth_request.credential_id) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response.nonce_len != SPDM_AUTH_NONCE_SIZE) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    session_info->auth.common.credential_id = credential_id;
    session_info->auth.usap.sequence_number = 1;
    libspdm_copy_mem(session_info->auth.usap.requester_nonce,
                     sizeof(session_info->auth.usap.requester_nonce),
                     spdm_auth_request.nonce,
                     sizeof(spdm_auth_request.nonce));
    libspdm_copy_mem(session_info->auth.usap.responder_nonce,
                     sizeof(session_info->auth.usap.responder_nonce),
                     spdm_auth_response.nonce,
                     sizeof(spdm_auth_response.nonce));

    /* -=[Update State Phase]=- */
    session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_START;
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    return status;
}
