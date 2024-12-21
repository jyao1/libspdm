/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t set_auth_policy_op;
    spdm_auth_policy_list_t policy_list_header;
    spdm_auth_policy_struct_for_dsp0289_t
        policies[LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT];
} libspdm_auth_set_auth_policy_request_max_t;

typedef struct {
    spdm_auth_message_header_t header;
    uint8_t dummy_data[sizeof(spdm_auth_error_code_data_t)];
} libspdm_auth_set_auth_policy_done_response_max_t;
#pragma pack()

libspdm_return_t libspdm_auth_set_auth_policy(
    void *context, uint32_t session_id,
    bool need_auth,
    uint8_t set_auth_policy_op,
    size_t policy_list_size,
    const void *policy_list)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    libspdm_auth_set_auth_policy_request_max_t spdm_auth_request;
    size_t spdm_auth_request_size;
    libspdm_auth_set_auth_policy_done_response_max_t spdm_auth_response;
    spdm_auth_error_response_t *spdm_auth_error;
    size_t spdm_auth_response_size;

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

    if (policy_list_size > sizeof(spdm_auth_policy_list_t) +
                           sizeof(spdm_auth_policy_struct_for_dsp0289_t) *
                           LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    /* -=[Construct Request Phase]=- */
    libspdm_zero_mem(&spdm_auth_request, sizeof(spdm_auth_request));
    spdm_auth_request.header.request_response_code = SPDM_AUTH_SET_AUTH_POLICY;
    spdm_auth_request.set_auth_policy_op = set_auth_policy_op;
    libspdm_copy_mem(&spdm_auth_request.policy_list_header,
                     sizeof(spdm_auth_request.policy_list_header) +
                     sizeof(spdm_auth_request.policies),
                     policy_list,
                     policy_list_size);
    spdm_auth_request_size = sizeof(spdm_auth_set_auth_policy_request_t) -
                             sizeof(spdm_auth_policy_list_t) +
                             policy_list_size;

    /* -=[Send Receive Phase]=- */
    spdm_auth_response_size = sizeof(spdm_auth_response);
    status = libspdm_auth_send_receive (spdm_context, session_id, need_auth,
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
    } else if (spdm_auth_response.header.request_response_code != SPDM_AUTH_SET_AUTH_POLICY_DONE) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_set_auth_policy_done_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    return status;
}
