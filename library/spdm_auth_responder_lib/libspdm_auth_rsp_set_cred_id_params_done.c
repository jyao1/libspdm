/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

libspdm_return_t libspdm_auth_get_response_set_cred_id_params_done(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response)
{
    const spdm_auth_set_cred_id_params_request_t *spdm_auth_request;
    spdm_auth_set_cred_id_params_done_response_t *spdm_auth_response;
    libspdm_session_info_t *session_info;
    bool ret;
    bool operation_failed;
    uint8_t device_state;

    spdm_auth_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_auth_request->header.request_response_code == SPDM_AUTH_SET_CRED_ID_PARAMS);

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

    device_state = libspdm_auth_device_get_device_provisioning_state(spdm_context, session_id);
    if ((device_state != SPDM_AUTH_DEVICE_PROVISION_STATE_DEFAULT_STATE) &&
        ((session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) ||
         (!has_auth))) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
            response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_auth_set_cred_id_params_request_t)) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }
    if (request_size < sizeof(spdm_auth_set_cred_id_params_request_t) +
                       spdm_auth_request->cred_params.credential_data_size) {
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    switch (spdm_auth_request->set_cred_info_op) {
    case SPDM_AUTH_SET_CRED_INFO_OP_LOCK:
    case SPDM_AUTH_SET_CRED_INFO_OP_UNLOCK:
        if ((session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) ||
            (!has_auth)) {
            return libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
                response_size, response);
        }
        break;
    case SPDM_AUTH_SET_CRED_INFO_OP_PARAMETER_CHANGE:
        break;
    default:
        return libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            response_size, response);
    }

    operation_failed = false;
    ret = libspdm_auth_device_set_cred_id_params (
        spdm_context, session_id, has_auth,
        spdm_auth_request->set_cred_info_op,
        sizeof(spdm_auth_credential_struct_t) +
        spdm_auth_request->cred_params.credential_data_size,
        &spdm_auth_request->cred_params,
        &operation_failed);
    if (!ret) {
        if (operation_failed) {
            return libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_OPERATION_FAILED,
                response_size, response);
        } else {
            return libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                response_size, response);
        }
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_set_cred_id_params_done_response_t));
    *response_size = sizeof(spdm_auth_set_cred_id_params_done_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_SET_CRED_ID_PARAMS_DONE;

    return LIBSPDM_STATUS_SUCCESS;
}
