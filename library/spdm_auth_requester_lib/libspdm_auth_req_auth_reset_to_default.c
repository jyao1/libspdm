/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t data_type;
    uint16_t credential_id;
    uint16_t sv_reset_data_type_count;
    uint8_t sv_reset_data_type_list[LIBSPDM_AUTH_MAX_SV_RESET_DATA_TYPE_LIST_BUFFER_SIZE];
} libspdm_auth_auth_reset_to_default_request_max_t;
#pragma pack()

libspdm_return_t libspdm_auth_auth_reset_to_default(
    void *context, uint32_t session_id,
    uint16_t data_type, uint16_t credential_id,
    uint16_t sv_reset_data_type_count, size_t sv_reset_data_type_list_size,
    const void *sv_reset_data_type_list)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    libspdm_auth_auth_reset_to_default_request_max_t spdm_auth_request;
    size_t spdm_auth_request_size;
    spdm_auth_auth_defaults_applied_response_t spdm_auth_response;
    spdm_auth_error_response_t *spdm_auth_error;
    size_t spdm_auth_response_size;
    size_t index;

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

    if (session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (sv_reset_data_type_list_size > LIBSPDM_AUTH_MAX_SV_RESET_DATA_TYPE_LIST_BUFFER_SIZE) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    /* -=[Construct Request Phase]=- */
    libspdm_zero_mem(&spdm_auth_request, sizeof(spdm_auth_request));
    spdm_auth_request.header.request_response_code = SPDM_AUTH_AUTH_RESET_TO_DEFAULT;
    spdm_auth_request.data_type = data_type;
    spdm_auth_request.credential_id = credential_id;
    spdm_auth_request.sv_reset_data_type_count = sv_reset_data_type_count;
    if (sv_reset_data_type_count != 0) {
        libspdm_copy_mem(&spdm_auth_request.sv_reset_data_type_list,
                        sizeof(spdm_auth_request.sv_reset_data_type_list),
                        sv_reset_data_type_list,
                        sv_reset_data_type_list_size);
    }
    spdm_auth_request_size = sizeof(spdm_auth_auth_reset_to_default_request_t) + sv_reset_data_type_list_size;

    /* -=[Send Receive Phase]=- */
    spdm_auth_response_size = sizeof(spdm_auth_response);
    status = libspdm_auth_send_receive (spdm_context, session_id, true,
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
    } else if (spdm_auth_response.header.request_response_code != SPDM_AUTH_AUTH_DEFAULTS_APPLIED) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_auth_response_size < sizeof(spdm_auth_auth_defaults_applied_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    if ((status == LIBSPDM_STATUS_RESET_REQUIRED_PEER) || (status == LIBSPDM_STATUS_SUCCESS)) {
        for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
            if ((credential_id != 0xFFFF) &&
                (credential_id != spdm_context->session_info[index].auth.common.credential_id)) {
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
    }
    return status;
}
