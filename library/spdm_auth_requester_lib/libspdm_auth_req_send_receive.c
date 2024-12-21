/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

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
uint8_t req_scratch_buffer[1024];
uint8_t rsp_scratch_buffer[1024];
uint8_t sign_msg_scratch_buffer[1024];

libspdm_return_t libspdm_auth_send_receive(
    void *context,
    uint32_t session_id,
    bool need_auth,
    size_t req_size,
    const void *req_data,
    size_t *rsp_size,
    void *rsp_data)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_return_t status;
    uint16_t dsp_number;
    uint16_t rsp_standard_id;
    uint8_t rsp_vendor_id_len;
    uint16_t rsp_dsp_number;
    size_t signature_size;
    size_t final_req_size;
    size_t final_rsp_size;
    spdm_auth_record_t *header_no_auth;
    spdm_auth_record_type_1_full_header_t *header_with_auth;
    uint8_t *ptr;
    bool ret;
    uint64_t auth_base_algo;
    uint64_t auth_base_hash_algo;
    spdm_auth_record_sign_header_t *sign_header;

    spdm_context = context;
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (need_auth) {
        if (session_info->auth.auth_session_state != LIBSPDM_AUTH_SESSION_STATE_START) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        if (session_info->auth.auth_session_process_type !=
            LIBSPDM_AUTH_SESSION_PROCESS_TYPE_USAP) {
            need_auth = false;
        }
    }

    if (need_auth) {
        ret = libspdm_auth_device_get_algo_from_credential_id (
            spdm_context, session_id,
            session_info->auth.common.credential_id, &auth_base_algo, &auth_base_hash_algo);
        if (!ret) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        signature_size = libspdm_auth_get_asym_signature_size(auth_base_algo);
        LIBSPDM_ASSERT(signature_size <= LIBSPDM_MAX_ASYM_SIG_SIZE);

        header_with_auth = (void *)req_scratch_buffer;
        header_with_auth->auth_record_type = SPDM_AUTH_RECORD_TYPE_MESSAGE_WITH_AUTH;
        header_with_auth->payload_len = sizeof(spdm_auth_record_type_msg_with_auth_t) +
                                        sizeof(spdm_auth_record_tag_t) + (uint32_t)signature_size +
                                        sizeof(uint32_t) + (uint32_t)req_size;
        header_with_auth->auth_rec_id = 0;
        header_with_auth->auth_tag_len = sizeof(spdm_auth_record_tag_t) + (uint32_t)signature_size;
        header_with_auth->credential_id = session_info->auth.common.credential_id;
        ptr = header_with_auth->signature;

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
            req_data,
            req_size
            );
        ret = libspdm_auth_device_requester_data_sign (
            context, session_id,
            session_info->auth.common.credential_id,
            session_info->auth.auth_version,
            sign_msg_scratch_buffer, req_size + sizeof(spdm_auth_record_sign_header_t),
            ptr, &signature_size
            );
        if (!ret) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        if (session_info->auth.usap.sequence_number == 0xFFFFFFFF) {
            libspdm_zero_mem(&session_info->auth.common, sizeof(session_info->auth.common));
            libspdm_zero_mem(&session_info->auth.usap, sizeof(session_info->auth.usap));
            session_info->auth.auth_session_state = LIBSPDM_AUTH_SESSION_STATE_END;
        } else {
            session_info->auth.usap.sequence_number++;
        }

        ptr += signature_size;
        *(uint32_t *)ptr = (uint32_t)req_size; /* msg_to_auth_payload_len */
        ptr += sizeof(uint32_t);
        libspdm_copy_mem(ptr,
                         (size_t)header_with_auth + sizeof(req_scratch_buffer) - (size_t)ptr,
                         req_data,
                         req_size
                         );
        final_req_size = sizeof(spdm_auth_record_t) + header_with_auth->payload_len;
    } else {
        header_no_auth = (void *)req_scratch_buffer;
        header_no_auth->auth_record_type = SPDM_AUTH_RECORD_TYPE_AUTH_MESSAGE;
        header_no_auth->payload_len = (uint32_t)req_size;
        libspdm_copy_mem(header_no_auth + 1,
                         sizeof(req_scratch_buffer) - sizeof(spdm_auth_record_t),
                         req_data,
                         req_size
                         );
        final_req_size = sizeof(spdm_auth_record_t) + header_no_auth->payload_len;
    }

    dsp_number = 289;
    rsp_standard_id = SPDM_REGISTRY_ID_DMTF_DSP;
    rsp_vendor_id_len = 2;
    rsp_dsp_number = 289;
    final_rsp_size = (uint16_t)sizeof(rsp_scratch_buffer);
    status = libspdm_vendor_send_request_receive_response (spdm_context, &session_id,
                                                           SPDM_REGISTRY_ID_DMTF_DSP,
                                                           2, &dsp_number,
                                                           (uint16_t)final_req_size,
                                                           req_scratch_buffer,
                                                           &rsp_standard_id,
                                                           &rsp_vendor_id_len, &rsp_dsp_number,
                                                           (uint16_t *)&final_rsp_size,
                                                           rsp_scratch_buffer
                                                           );
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    if ((rsp_standard_id != SPDM_REGISTRY_ID_DMTF_DSP) ||
        (rsp_vendor_id_len != 2) ||
        (rsp_dsp_number != 289)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (final_rsp_size < sizeof(spdm_auth_record_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    header_no_auth = (void *)rsp_scratch_buffer;
    if ((header_no_auth->auth_record_type != SPDM_AUTH_RECORD_TYPE_AUTH_MESSAGE) ||
        (header_no_auth->payload_len >
         final_rsp_size - sizeof(spdm_auth_record_t))) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (*rsp_size < header_no_auth->payload_len) {
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }
    *rsp_size = header_no_auth->payload_len;
    libspdm_copy_mem(rsp_data,
                     *rsp_size,
                     header_no_auth + 1,
                     header_no_auth->payload_len
                     );

    return LIBSPDM_STATUS_SUCCESS;
}
