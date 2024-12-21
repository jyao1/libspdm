/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_responder_lib.h"

#pragma pack(1)
typedef struct {
    uint8_t auth_record_type;
    uint8_t reserved;
    uint32_t payload_len;
    uint32_t auth_rec_id;
    uint32_t auth_tag_len;
    uint16_t credential_id;
    uint8_t signature[LIBSPDM_MAX_ASYM_SIG_SIZE];
    uint32_t msg_to_auth_payload_len;
} spdm_auth_record_type_1_full_header_t;
#pragma pack()

// JYAO1
uint8_t sign_msg_scratch_buffer[1024];

/**
 *  Process the SPDM vendor defined request and return the response.
 *
 *  @param request       the SPDM vendor defined request message, start from spdm_message_header_t.
 *  @param request_size  size in bytes of request.
 *  @param response      the SPDM vendor defined response message, start from spdm_message_header_t.
 *  @param response_size size in bytes of response.
 *
 *  @retval LIBSPDM_STATUS_SUCCESS The request is processed and the response is returned.
 *  @return ERROR          The request is not processed.
 **/
libspdm_return_t libspdm_auth_get_response_vendor_defined_request(
    void *spdm_context,
    uint32_t session_id,
    const void *request,
    size_t request_size,
    void *response,
    size_t *response_size)
{
    libspdm_session_info_t *session_info;
    const spdm_auth_vendor_defined_request_t *spdm_request;
    spdm_auth_vendor_defined_response_t *spdm_response;
    size_t index;
    size_t rsp_payload_len;
    size_t req_payload_len;
    libspdm_return_t status;
    const spdm_auth_message_header_t *req_spdm_auth_header;
    spdm_auth_message_header_t *rsp_spdm_auth_header;
    spdm_auth_record_t *header_no_auth;
    spdm_auth_record_type_1_full_header_t *header_with_auth;
    size_t signature_size;
    uint8_t *ptr;
    bool has_auth;
    bool auth_failed;
    bool ret;
    uint64_t auth_base_algo;
    uint64_t auth_base_hash_algo;
    spdm_auth_record_sign_header_t *sign_header;

    typedef struct {
        uint8_t request_response_code;
        libspdm_auth_get_response_func_t get_response_func;
    } libspdm_auth_get_response_struct_t;

    libspdm_auth_get_response_struct_t get_response_struct[] = {
        { SPDM_AUTH_GET_AUTH_VERSION, libspdm_auth_get_response_auth_version },
        { SPDM_AUTH_SELECT_AUTH_VERSION, libspdm_auth_get_response_select_auth_version_rsp },
        { SPDM_AUTH_GET_AUTH_CAPABILITIES, libspdm_auth_get_response_auth_capabilities },
        { SPDM_AUTH_SET_CRED_ID_PARAMS, libspdm_auth_get_response_set_cred_id_params_done },
        { SPDM_AUTH_GET_CRED_ID_PARAMS, libspdm_auth_get_response_cred_id_params },
        { SPDM_AUTH_SET_AUTH_POLICY, libspdm_auth_get_response_set_auth_policy_done },
        { SPDM_AUTH_GET_AUTH_POLICY, libspdm_auth_get_response_auth_policy },
        { SPDM_AUTH_GET_AUTH_PROCESSES, libspdm_auth_get_response_auth_processes },
        { SPDM_AUTH_KILL_AUTH_PROCESS, libspdm_auth_get_response_process_killed },
        { SPDM_AUTH_START_AUTH, libspdm_auth_get_response_start_auth_rsp },
        { SPDM_AUTH_END_AUTH, libspdm_auth_get_response_end_auth_rsp },
        { SPDM_AUTH_ELEVATE_PRIVILEGE, libspdm_auth_get_response_privilege_elevated },
        { SPDM_AUTH_END_ELEVATED_PRIVILEGE, libspdm_auth_get_response_elevated_privilege_ended },
        { SPDM_AUTH_TAKE_OWNERSHIP, libspdm_auth_get_response_ownership_taken },
        { SPDM_AUTH_AUTH_RESET_TO_DEFAULT, libspdm_auth_get_response_auth_defaults_applied },
    };

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    spdm_request = request;
    spdm_response = response;
    if (request_size < sizeof(spdm_auth_vendor_defined_request_t) +
                       sizeof(spdm_auth_record_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    LIBSPDM_ASSERT (*response_size > sizeof(spdm_auth_vendor_defined_response_t) +
                                     sizeof(spdm_auth_record_t));

    if (spdm_request->header.request_response_code != SPDM_VENDOR_DEFINED_REQUEST) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->auth_vendor_header.standard_id != SPDM_REGISTRY_ID_DMTF_DSP) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->auth_vendor_header.len !=
        sizeof(spdm_request->auth_vendor_header.dmtf_spec_id)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->auth_vendor_header.dmtf_spec_id != 289) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->auth_vendor_header.payload_length >
        request_size - sizeof(spdm_auth_vendor_defined_request_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_request->auth_vendor_header.payload_length <
        sizeof(spdm_auth_record_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    rsp_payload_len = *response_size - sizeof(spdm_auth_vendor_defined_response_t) -
                      sizeof(spdm_auth_record_t);
    rsp_spdm_auth_header = (void *)((uint8_t *)response + sizeof(spdm_auth_vendor_defined_response_t) +
                                    sizeof(spdm_auth_record_t));

    header_with_auth = (void *)((uint8_t *)request +
                                sizeof(spdm_auth_vendor_defined_request_t));
    header_no_auth = (void *)header_with_auth;
    auth_failed = false;
    if (header_with_auth->auth_record_type == SPDM_AUTH_RECORD_TYPE_MESSAGE_WITH_AUTH) {
        if ((session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) ||
            (session_info->auth.auth_session_process_type !=
             LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP)) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }

        if (spdm_request->auth_vendor_header.payload_length <
            sizeof(spdm_auth_record_t) + sizeof(spdm_auth_record_type_msg_with_auth_t) +
            sizeof(spdm_auth_record_tag_t)) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }

        if (header_with_auth->credential_id != session_info->auth.common.credential_id) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }
        ret = libspdm_auth_device_get_algo_from_credential_id (
            spdm_context, session_id,
            header_with_auth->credential_id, &auth_base_algo, &auth_base_hash_algo);
        if (!ret) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }

        signature_size = libspdm_auth_get_asym_signature_size(auth_base_algo);
        LIBSPDM_ASSERT(signature_size <= LIBSPDM_MAX_ASYM_SIG_SIZE);
        if (header_with_auth->auth_tag_len != sizeof(spdm_auth_record_tag_t) + (uint32_t)signature_size) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }
        if (spdm_request->auth_vendor_header.payload_length <
            sizeof(spdm_auth_record_t) + sizeof(spdm_auth_record_type_msg_with_auth_t) +
            sizeof(spdm_auth_record_tag_t) + signature_size) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }
        ptr = header_with_auth->signature;
        ptr += signature_size;
        req_payload_len = *(uint32_t *)ptr; /* msg_to_auth_payload_len */
        if (req_payload_len > spdm_request->auth_vendor_header.payload_length -
                              (sizeof(spdm_auth_record_t) +
                              sizeof(spdm_auth_record_type_msg_with_auth_t) +
                              sizeof(spdm_auth_record_tag_t) + signature_size)) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }
        if (header_with_auth->payload_len != sizeof(spdm_auth_record_type_msg_with_auth_t) +
                                             sizeof(spdm_auth_record_tag_t) + (uint32_t)signature_size +
                                             sizeof(uint32_t) + req_payload_len) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }

        ptr += sizeof(uint32_t);
        req_spdm_auth_header = (void *)ptr;

        sign_header = (void *)sign_msg_scratch_buffer;
        sign_header->credential_id = session_info->auth.common.credential_id;
        sign_header->sequence_number = session_info->auth.usap.sequence_number;
        libspdm_copy_mem(
            sign_header->requester_nonce,
            sizeof(sign_header->requester_nonce),
            session_info->auth.usap.requester_nonce,
            sizeof(session_info->auth.usap.requester_nonce)
            );
        libspdm_copy_mem(
            sign_header->responder_nonce,
            sizeof(sign_header->responder_nonce),
            session_info->auth.usap.responder_nonce,
            sizeof(session_info->auth.usap.responder_nonce)
            );
        libspdm_copy_mem(
            sign_header + 1,
            sizeof(sign_msg_scratch_buffer) - sizeof(spdm_auth_record_sign_header_t),
            (const void *)req_spdm_auth_header,
            req_payload_len
            );
        ret = libspdm_auth_device_requester_data_verify (
            spdm_context, session_id,
            session_info->auth.common.credential_id,
            session_info->auth.auth_version,
            sign_msg_scratch_buffer, req_payload_len + sizeof(spdm_auth_record_sign_header_t),
            header_with_auth->signature, signature_size
            );
        if (!ret) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_ACCESS_DENIED,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }

        has_auth = true;
    } else if (header_no_auth->auth_record_type == SPDM_AUTH_RECORD_TYPE_AUTH_MESSAGE) {
        if (spdm_request->auth_vendor_header.payload_length <
            sizeof(spdm_auth_record_t)) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }

        req_spdm_auth_header = (void *)(header_no_auth + 1);
        req_payload_len = header_no_auth->payload_len;
        if (req_payload_len > spdm_request->auth_vendor_header.payload_length -
                              sizeof(spdm_auth_record_t)) {
            libspdm_auth_generate_error_response(
                spdm_context,
                SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
                &rsp_payload_len, rsp_spdm_auth_header);
            goto build_final_response;
        }
        has_auth = false;
    } else {
        libspdm_auth_generate_error_response(
            spdm_context,
            SPDM_AUTH_ERROR_CODE_INVALID_REQUEST,
            &rsp_payload_len, rsp_spdm_auth_header);
        goto build_final_response;
    }

    if (!has_auth) {
        if ((session_info->auth.auth_session_process_type == LIBSPDM_AUTH_SESSION_PROCESS_TYPE_SEAP) &&
            (session_info->auth.auth_session_state == LIBSPDM_AUTH_SESSION_STATE_START)) {
            has_auth = true;
        }
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(get_response_struct); index++) {
        if ((req_spdm_auth_header->request_response_code ==
             get_response_struct[index].request_response_code)) {
            status = get_response_struct[index].get_response_func (
                spdm_context, session_id, has_auth,
                req_payload_len,
                req_spdm_auth_header,
                &rsp_payload_len,
                rsp_spdm_auth_header
                );

            /* update session state after get the response */
            if ((session_info->auth.auth_session_process_type ==
                 LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP) &&
                has_auth) {
                if (session_info->auth.usap.sequence_number == 0xFFFFFFFF) {
                    libspdm_zero_mem(&session_info->auth.common, sizeof(session_info->auth.common));
                    libspdm_zero_mem(&session_info->auth.usap, sizeof(session_info->auth.usap));
                    session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_END;
                } else {
                    session_info->auth.usap.sequence_number++;
                }
            }

            goto build_final_response;
        }
    }
    /* opcode mismatch */
    libspdm_auth_generate_error_response(
        spdm_context,
        SPDM_AUTH_ERROR_CODE_UNSUPPORTED_REQUEST,
        &rsp_payload_len, rsp_spdm_auth_header);

build_final_response:
    libspdm_zero_mem (spdm_response, sizeof(spdm_auth_vendor_defined_response_t));
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
    spdm_response->auth_vendor_header.standard_id =
        spdm_request->auth_vendor_header.standard_id;
    spdm_response->auth_vendor_header.len =
        sizeof(spdm_response->auth_vendor_header.dmtf_spec_id);
    spdm_response->auth_vendor_header.dmtf_spec_id =
        spdm_request->auth_vendor_header.dmtf_spec_id;
    spdm_response->auth_vendor_header.payload_length =
        (uint16_t)(rsp_payload_len + sizeof(spdm_auth_record_t));

    header_no_auth = (void *)((uint8_t *)response + sizeof(spdm_auth_vendor_defined_response_t));
    header_no_auth->auth_record_type = SPDM_AUTH_RECORD_TYPE_AUTH_MESSAGE;
    header_no_auth->payload_len = (uint32_t)rsp_payload_len;

    *response_size = sizeof(spdm_auth_vendor_defined_response_t) +
        sizeof(spdm_auth_record_t) + header_no_auth->payload_len;

    return LIBSPDM_STATUS_SUCCESS;
}
