/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t policy_attributes;
    spdm_auth_policy_list_t policy_list_header;
    spdm_auth_policy_struct_for_dsp0289_t
        policies[LIBSPDM_AUTH_MAX_POLICY_LIST_COUNT];
} libspdm_auth_auth_policy_response_max_t;
#pragma pack()

libspdm_return_t libspdm_auth_get_auth_policy(
    void *context, uint32_t session_id,
    bool need_auth,
    uint16_t credential_id,
    uint16_t *policy_attributes,
    size_t *policy_list_size,
    void *policy_list)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    spdm_auth_get_auth_policy_request_t spdm_auth_request;
    size_t spdm_auth_request_size;
    libspdm_auth_auth_policy_response_max_t spdm_auth_response;
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

    /* -=[Construct Request Phase]=- */
    libspdm_zero_mem(&spdm_auth_request, sizeof(spdm_auth_request));
    spdm_auth_request.header.request_response_code = SPDM_AUTH_GET_AUTH_POLICY;
    spdm_auth_request.credential_id = credential_id;
    spdm_auth_request_size = sizeof(spdm_auth_get_auth_policy_request_t);

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
    } else if (spdm_auth_response.header.request_response_code != SPDM_AUTH_AUTH_POLICY) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_auth_policy_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_auth_policy_response_t) +
                                  spdm_auth_response.policy_list_header.num_of_policies *
                                  sizeof(spdm_auth_policy_struct_for_dsp0289_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_auth_response.policy_list_header.credential_id != credential_id) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    spdm_auth_response_size = sizeof(spdm_auth_auth_policy_response_t) +
                              spdm_auth_response.policy_list_header.num_of_policies *
                              sizeof(spdm_auth_policy_struct_for_dsp0289_t);

    if (*policy_list_size < sizeof(spdm_auth_policy_list_t) +
                            spdm_auth_response.policy_list_header.num_of_policies *
                            sizeof(spdm_auth_policy_struct_for_dsp0289_t)) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }
    *policy_list_size = sizeof(spdm_auth_policy_list_t) +
                        spdm_auth_response.policy_list_header.num_of_policies *
                        sizeof(spdm_auth_policy_struct_for_dsp0289_t);

    *policy_attributes = spdm_auth_response.policy_attributes;
    libspdm_copy_mem(policy_list,
                     *policy_list_size,
                     &spdm_auth_response.policy_list_header,
                     sizeof(spdm_auth_policy_list_t) +
                     spdm_auth_response.policy_list_header.num_of_policies *
                     sizeof(spdm_auth_policy_struct_for_dsp0289_t)
                     );

    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    return status;
}
