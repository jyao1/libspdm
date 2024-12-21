/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

libspdm_return_t libspdm_auth_get_response_auth_processes(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_get_auth_processes_request_t *spdm_auth_request;
    spdm_auth_auth_processes_response_t *spdm_auth_response;
    uint16_t auth_proc_info_count;
    spdm_auth_auth_proc_info_t auth_proc_info_list[2];
    libspdm_session_info_t *session_info;
    uint16_t session_credential_id;
    uint16_t credential_privileges;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_GET_AUTH_PROCESSES);

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
    if (request_size < sizeof(spdm_auth_get_auth_processes_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    if (spdm_auth_request->credential_id != SPDM_AUTH_CREDENTIAL_ID_ALL) {
        session_credential_id = libspdm_get_credential_id_from_session(spdm_context, session_id);
        credential_privileges = libspdm_auth_device_get_credential_privileges(
            spdm_context, session_id, session_credential_id);
        if ((credential_privileges &
            SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_RETRIEVE_AUTH_PROC_LIST) == 0) {
            return libspdm_auth_generate_error_response(
                    spdm_context,
                    SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
                    response_size, response);
        }
    }

    auth_proc_info_count = 1; // JYAO1
    auth_proc_info_list[0].credential_id = spdm_auth_request->credential_id;
    switch (session_info->auth.auth_session_process_type) {
    case LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP:
        auth_proc_info_list[0].auth_process_type = SPDM_AUTH_AUTH_PROC_TYPE_ACTIVE_USAS;
        break;
    case LIBSPDM_AUTH_SESSION_PROCESS_TYPE_SEAP:
        auth_proc_info_list[0].auth_process_type = SPDM_AUTH_AUTH_PROC_TYPE_ACTIVE_SEAS;
        break;
    default:
        LIBSPDM_ASSERT(false);
    }
    libspdm_get_auth_proc_id_from_session (
        spdm_context, session_info,
        &auth_proc_info_list[0].auth_proc_id
    );

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_auth_processes_response_t) +
                                     auth_proc_info_count *
                                     sizeof(spdm_auth_auth_proc_info_t));
    *response_size = sizeof(spdm_auth_auth_processes_response_t) +
                     auth_proc_info_count *
                     sizeof(spdm_auth_auth_proc_info_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_AUTH_PROCESSES;
    spdm_auth_response->auth_proc_info_count = auth_proc_info_count;
    libspdm_copy_mem(spdm_auth_response + 1,
                     auth_proc_info_count *
                     sizeof(spdm_auth_auth_proc_info_t),
                     auth_proc_info_list,
                     auth_proc_info_count *
                     sizeof(spdm_auth_auth_proc_info_t));

    return LIBSPDM_STATUS_SUCCESS;
}
