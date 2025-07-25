/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification;
    uint8_t other_params_support;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint32_t pqc_asym_algo;
    uint8_t reserved2[8];
    uint8_t ext_asym_count;
    uint8_t ext_hash_count;
    uint8_t reserved3;
    uint8_t mel_specification;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[
        SPDM_NEGOTIATE_ALGORITHMS_MAX_NUM_STRUCT_TABLE_ALG_14];
} libspdm_negotiate_algorithms_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification_sel;
    uint8_t other_params_selection;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_sel;
    uint32_t base_hash_sel;
    uint32_t pqc_asym_sel;
    uint8_t reserved2[7];
    uint8_t mel_specification_sel;
    uint8_t ext_asym_sel_count;
    uint8_t ext_hash_sel_count;
    uint16_t reserved3;
    uint32_t ext_asym_sel;
    uint32_t ext_hash_sel;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[
        SPDM_NEGOTIATE_ALGORITHMS_MAX_NUM_STRUCT_TABLE_ALG_14];
} libspdm_algorithms_response_max_t;
#pragma pack()

/**
 * This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.
 *
 * @param  spdm_context A pointer to the SPDM context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS
 *         NEGOTIATE_ALGORITHMS was sent and ALGORITHMS was received.
 * @retval LIBSPDM_STATUS_INVALID_STATE_LOCAL
 *         Cannot send NEGOTIATE_ALGORITHMS due to Requester's state.
 * @retval LIBSPDM_STATUS_INVALID_MSG_SIZE
 *         The size of the ALGORITHMS response is invalid.
 * @retval LIBSPDM_STATUS_INVALID_MSG_FIELD
 *         The ALGORITHMS response contains one or more invalid fields.
 * @retval LIBSPDM_STATUS_ERROR_PEER
 *         The Responder returned an unexpected error.
 * @retval LIBSPDM_STATUS_BUSY_PEER
 *         The Responder continually returned Busy error messages.
 * @retval LIBSPDM_STATUS_RESYNCH_PEER
 *         The Responder returned a RequestResynch error message.
 * @retval LIBSPDM_STATUS_BUFFER_FULL
 *         The buffer used to store transcripts is exhausted.
 * @retval LIBSPDM_STATUS_NEGOTIATION_FAIL
 *         The Requester and Responder could not agree on mutual algorithms.
 *         Note: This return value may be removed in the future.
 **/
static libspdm_return_t libspdm_try_negotiate_algorithms(libspdm_context_t *spdm_context)
{
    libspdm_return_t status;
    libspdm_negotiate_algorithms_request_mine_t *spdm_request;
    size_t spdm_request_size;
    libspdm_algorithms_response_max_t *spdm_response;
    size_t spdm_response_size;
    uint32_t algo_size;
    uint32_t pqc_algo_size;
    size_t index = 0;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    uint8_t fixed_alg_size;
    uint8_t ext_alg_count;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;
    uint8_t alg_type_pre;
    uint8_t req_param1 = 0;

    /* -=[Verify State Phase]=- */
    if (spdm_context->connection_info.connection_state !=
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL, SPDM_NEGOTIATE_ALGORITHMS);

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    LIBSPDM_ASSERT(spdm_request_size >= sizeof(spdm_negotiate_algorithms_request_t));
    libspdm_zero_mem(spdm_request, spdm_request_size);
    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        /* Number of Algorithms Structure Tables based on supported algorithms */
        if (spdm_context->local_context.algorithm.dhe_named_group != 0) {
            req_param1++;
        }
        if (spdm_context->local_context.algorithm.aead_cipher_suite != 0) {
            req_param1++;
        }
        if (spdm_context->local_context.algorithm.req_base_asym_alg != 0) {
            req_param1++;
        }
        if (spdm_context->local_context.algorithm.key_schedule != 0) {
            req_param1++;
        }
        LIBSPDM_ASSERT(req_param1 <=
                       SPDM_NEGOTIATE_ALGORITHMS_MAX_NUM_STRUCT_TABLE_ALG);
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            if (spdm_context->local_context.algorithm.req_pqc_asym_alg) {
                req_param1++;
            }
            if (spdm_context->local_context.algorithm.kem_alg) {
                req_param1++;
            }
            LIBSPDM_ASSERT(req_param1 <=
                           SPDM_NEGOTIATE_ALGORITHMS_MAX_NUM_STRUCT_TABLE_ALG_14);
        }
        spdm_request->header.param1 = req_param1;
        spdm_request->length =
            offsetof(libspdm_negotiate_algorithms_request_mine_t, struct_table) +
            req_param1 * sizeof(spdm_negotiate_algorithms_common_struct_table_t);
    } else {
        spdm_request->length = offsetof(libspdm_negotiate_algorithms_request_mine_t, struct_table);
        spdm_request->header.param1 = 0;
    }

    LIBSPDM_ASSERT(spdm_request_size >= spdm_request->length);
    spdm_request->header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request->header.param2 = 0;
    spdm_request->measurement_specification =
        spdm_context->local_context.algorithm.measurement_spec;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_request->other_params_support =
            spdm_context->local_context.algorithm.other_params_support &
            SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK;
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            spdm_request->other_params_support =
                spdm_context->local_context.algorithm.other_params_support;
            spdm_request->mel_specification =
                spdm_context->local_context.algorithm.mel_spec;
        }
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        switch (spdm_context->connection_info.capability.flags &
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP) {
        case 0:
            spdm_context->connection_info.multi_key_conn_rsp = false;
            break;
        case SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY:
            spdm_context->connection_info.multi_key_conn_rsp = true;
            break;
        case SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG:
            if ((spdm_context->local_context.algorithm.other_params_support &
                 SPDM_ALGORITHMS_MULTI_KEY_CONN) == 0) {
                spdm_context->connection_info.multi_key_conn_rsp = false;
            } else {
                spdm_context->connection_info.multi_key_conn_rsp = true;
            }
            break;
        default:
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (spdm_context->connection_info.multi_key_conn_rsp) {
            spdm_request->other_params_support |= SPDM_ALGORITHMS_MULTI_KEY_CONN;
        } else {
            spdm_request->other_params_support &= ~SPDM_ALGORITHMS_MULTI_KEY_CONN;
        }
    }
    spdm_request->base_asym_algo = spdm_context->local_context.algorithm.base_asym_algo;
    spdm_request->base_hash_algo = spdm_context->local_context.algorithm.base_hash_algo;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_request->pqc_asym_algo = spdm_context->local_context.algorithm.pqc_asym_algo;
    }
    spdm_request->ext_asym_count = 0;
    spdm_request->ext_hash_count = 0;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        /* ReqAlgStruct order based on by AlgType */
        if (spdm_context->local_context.algorithm.dhe_named_group) {
            spdm_request->struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
            spdm_request->struct_table[index].alg_count = 0x20;
            spdm_request->struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.dhe_named_group;
            index++;
        }
        if (spdm_context->local_context.algorithm.aead_cipher_suite) {
            spdm_request->struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
            spdm_request->struct_table[index].alg_count = 0x20;
            spdm_request->struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.aead_cipher_suite;
            index++;
        }
        if (spdm_context->local_context.algorithm.req_base_asym_alg) {
            spdm_request->struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
            spdm_request->struct_table[index].alg_count = 0x20;
            spdm_request->struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.req_base_asym_alg;
            index++;
        }
        if (spdm_context->local_context.algorithm.key_schedule) {
            spdm_request->struct_table[index].alg_type =
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
            spdm_request->struct_table[index].alg_count = 0x20;
            spdm_request->struct_table[index].alg_supported =
                spdm_context->local_context.algorithm.key_schedule;
            index++;
        }
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            if (spdm_context->local_context.algorithm.req_pqc_asym_alg) {
                LIBSPDM_ASSERT(spdm_context->local_context.algorithm.req_pqc_asym_alg < 0x10000);
                spdm_request->struct_table[index].alg_type =
                    SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG;
                spdm_request->struct_table[index].alg_count = 0x20;
                spdm_request->struct_table[index].alg_supported =
                    (uint16_t)spdm_context->local_context.algorithm.req_pqc_asym_alg;
                index++;
            }
            if (spdm_context->local_context.algorithm.kem_alg) {
                LIBSPDM_ASSERT(spdm_context->local_context.algorithm.kem_alg < 0x10000);
                spdm_request->struct_table[index].alg_type =
                    SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG;
                spdm_request->struct_table[index].alg_count = 0x20;
                spdm_request->struct_table[index].alg_supported =
                    (uint16_t)spdm_context->local_context.algorithm.kem_alg;
                index++;
            }
        }
        LIBSPDM_ASSERT(index == spdm_request->header.param1);
    }
    spdm_request_size = spdm_request->length;

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, NULL, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    status = libspdm_receive_spdm_response(spdm_context, NULL, &spdm_response_size,
                                           (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_simple_error_response(spdm_context, spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_ALGORITHMS) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_algorithms_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (!libspdm_onehot0(spdm_response->measurement_specification_sel)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if (!libspdm_onehot0(spdm_response->other_params_selection &
                             SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK)) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }
    if (!libspdm_onehot0(spdm_response->measurement_hash_algo)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (!libspdm_onehot0(spdm_response->base_asym_sel)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (!libspdm_onehot0(spdm_response->base_hash_sel)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
        if (!libspdm_onehot0(spdm_response->pqc_asym_sel)) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }
    if (spdm_response->ext_asym_sel_count > 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->ext_hash_sel_count > 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size <
        sizeof(spdm_algorithms_response_t) +
        sizeof(uint32_t) * spdm_response->ext_asym_sel_count +
        sizeof(uint32_t) * spdm_response->ext_hash_sel_count +
        sizeof(spdm_negotiate_algorithms_common_struct_table_t) * spdm_response->header.param1) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    struct_table =
        (void *)((size_t)spdm_response +
                 sizeof(spdm_algorithms_response_t) +
                 sizeof(uint32_t) * spdm_response->ext_asym_sel_count +
                 sizeof(uint32_t) * spdm_response->ext_hash_sel_count);
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        alg_type_pre = struct_table->alg_type;
        /* header.param1 is implicitly checked through spdm_response_size. */
        for (index = 0; index < spdm_response->header.param1; index++) {
            if ((size_t)spdm_response + spdm_response_size < (size_t)struct_table) {
                status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
                goto receive_done;
            }
            if ((size_t)spdm_response + spdm_response_size - (size_t)struct_table <
                sizeof(spdm_negotiate_algorithms_common_struct_table_t)) {
                status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
                goto receive_done;
            }
            if ((struct_table->alg_type < SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE) ||
                (struct_table->alg_type >
                 SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG)) {
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto receive_done;
            }
            if ((spdm_response->header.spdm_version < SPDM_MESSAGE_VERSION_14) &&
                (struct_table->alg_type >
                 SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE)) {
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto receive_done;
            }
            /* AlgType shall monotonically increase for subsequent entries. */
            if ((index != 0) && (struct_table->alg_type <= alg_type_pre)) {
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto receive_done;
            }
            alg_type_pre = struct_table->alg_type;
            fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
            ext_alg_count = struct_table->alg_count & 0xF;
            if (fixed_alg_size != 2) {
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto receive_done;
            }
            if (ext_alg_count > 0) {
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto receive_done;
            }
            if (!libspdm_onehot0(struct_table->alg_supported)) {
                status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                goto receive_done;
            }
            if ((size_t)spdm_response + spdm_response_size -
                (size_t)struct_table - sizeof(spdm_negotiate_algorithms_common_struct_table_t) <
                sizeof(uint32_t) * ext_alg_count) {
                status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
                goto receive_done;
            }
            struct_table =
                (void *)((size_t)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }
    }

    spdm_response_size = (size_t)struct_table - (size_t)spdm_response;
    if (spdm_response_size != spdm_response->length) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    /* -=[Process Response Phase]=- */
    status = libspdm_append_message_a(spdm_context, spdm_request, spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    status = libspdm_append_message_a(spdm_context, spdm_response, spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    spdm_context->connection_info.algorithm.measurement_spec =
        spdm_response->measurement_specification_sel;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.algorithm.other_params_support =
            spdm_response->other_params_selection & SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK;
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            spdm_context->connection_info.algorithm.other_params_support =
                spdm_response->other_params_selection;
            spdm_context->connection_info.algorithm.mel_spec =
                spdm_response->mel_specification_sel;
        }
    }
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        spdm_response->measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = spdm_response->base_asym_sel;
    spdm_context->connection_info.algorithm.base_hash_algo = spdm_response->base_hash_sel;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
        spdm_context->connection_info.algorithm.pqc_asym_algo = spdm_response->pqc_asym_sel;
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) &&
        (spdm_request->measurement_specification != 0)) {
        if (spdm_context->connection_info.algorithm.measurement_spec !=
            SPDM_MEASUREMENT_SPECIFICATION_DMTF) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
        algo_size = libspdm_get_measurement_hash_size(
            spdm_context->connection_info.algorithm.measurement_hash_algo);
        if (algo_size == 0) {
            status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
            goto receive_done;
        }
    } else {
        if (spdm_context->connection_info.algorithm.measurement_spec != 0) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
        algo_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
        if (algo_size == 0) {
            status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
            goto receive_done;
        }
        if ((spdm_context->connection_info.algorithm.base_hash_algo &
             spdm_context->local_context.algorithm.base_hash_algo) == 0) {
            status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
            goto receive_done;
        }
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) ||
        libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
        algo_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            pqc_algo_size = libspdm_get_pqc_asym_signature_size(
                spdm_context->connection_info.algorithm.pqc_asym_algo);
        } else {
            pqc_algo_size = 0;
        }
        if (((algo_size == 0) && (pqc_algo_size == 0)) ||
            ((algo_size != 0) && (pqc_algo_size != 0))) {
            status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
            goto receive_done;
        }
        if ((algo_size != 0) &&
            ((spdm_context->connection_info.algorithm.base_asym_algo &
              spdm_context->local_context.algorithm.base_asym_algo) == 0)) {
            status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
            goto receive_done;
        }
        if ((pqc_algo_size != 0) &&
            ((spdm_context->connection_info.algorithm.pqc_asym_algo &
              spdm_context->local_context.algorithm.pqc_asym_algo) == 0)) {
            status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
            goto receive_done;
        }
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        struct_table =
            (void *)((size_t)spdm_response +
                     sizeof(spdm_algorithms_response_t) +
                     sizeof(uint32_t) * spdm_response->ext_asym_sel_count +
                     sizeof(uint32_t) * spdm_response->ext_hash_sel_count);
        for (index = 0; index < spdm_response->header.param1; index++) {
            switch (struct_table->alg_type) {
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
                spdm_context->connection_info.algorithm.dhe_named_group =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
                spdm_context->connection_info.algorithm.aead_cipher_suite =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
                spdm_context->connection_info.algorithm.req_base_asym_alg =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
                spdm_context->connection_info.algorithm.key_schedule =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG:
                spdm_context->connection_info.algorithm.req_pqc_asym_alg =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG:
                spdm_context->connection_info.algorithm.kem_alg =
                    struct_table->alg_supported;
                break;
            }
            ext_alg_count = struct_table->alg_count & 0xF;
            struct_table =
                (void *)((size_t)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }

        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
            algo_size = libspdm_get_dhe_pub_key_size(
                spdm_context->connection_info.algorithm.dhe_named_group);
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
                pqc_algo_size = libspdm_get_kem_encap_key_size(
                    spdm_context->connection_info.algorithm.kem_alg);
            } else {
                pqc_algo_size = 0;
            }
            if (((algo_size == 0) && (pqc_algo_size == 0)) ||
                ((algo_size != 0) && (pqc_algo_size != 0))) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if ((algo_size != 0) &&
                ((spdm_context->connection_info.algorithm.dhe_named_group &
                  spdm_context->local_context.algorithm.dhe_named_group) == 0)) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if ((pqc_algo_size != 0) &&
                ((spdm_context->connection_info.algorithm.kem_alg &
                  spdm_context->local_context.algorithm.kem_alg) == 0)) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
            libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
            algo_size = libspdm_get_aead_key_size(
                spdm_context->connection_info.algorithm.aead_cipher_suite);
            if (algo_size == 0) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if ((spdm_context->connection_info.algorithm.aead_cipher_suite &
                 spdm_context->local_context.algorithm.aead_cipher_suite) == 0) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
            algo_size = libspdm_get_req_asym_signature_size(
                spdm_context->connection_info.algorithm.req_base_asym_alg);
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
                pqc_algo_size = libspdm_get_req_pqc_asym_signature_size(
                    spdm_context->connection_info.algorithm.req_pqc_asym_alg);
            } else {
                pqc_algo_size = 0;
            }
            if (((algo_size == 0) && (pqc_algo_size == 0)) ||
                ((algo_size != 0) && (pqc_algo_size != 0))) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if ((algo_size != 0) &&
                ((spdm_context->connection_info.algorithm.req_base_asym_alg &
                  spdm_context->local_context.algorithm.req_base_asym_alg) == 0)) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if ((pqc_algo_size != 0) &&
                ((spdm_context->connection_info.algorithm.req_pqc_asym_alg &
                  spdm_context->local_context.algorithm.req_pqc_asym_alg) == 0)) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
        }
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
            libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
            if (spdm_context->connection_info.algorithm.key_schedule !=
                SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if ((spdm_context->connection_info.algorithm.key_schedule &
                 spdm_context->local_context.algorithm.key_schedule) == 0) {
                status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                goto receive_done;
            }
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
                if (libspdm_is_capabilities_flag_supported(
                        spdm_context, true, 0,
                        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP) &&
                    (spdm_request->mel_specification != 0)) {
                    if (spdm_context->connection_info.algorithm.mel_spec !=
                        SPDM_MEL_SPECIFICATION_DMTF) {
                        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                        goto receive_done;
                    }
                } else {
                    if (spdm_context->connection_info.algorithm.mel_spec != 0) {
                        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
                        goto receive_done;
                    }
                }
            }
        }

        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            if ((spdm_context->connection_info.algorithm.other_params_support &
                 SPDM_ALGORITHMS_MULTI_KEY_CONN) == 0) {
                if ((spdm_context->local_context.capability.flags &
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP) ==
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY) {
                    status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                    goto receive_done;
                }
                spdm_context->connection_info.multi_key_conn_req = false;
            } else {
                if ((spdm_context->local_context.capability.flags &
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP) == 0) {
                    status = LIBSPDM_STATUS_NEGOTIATION_FAIL;
                    goto receive_done;
                }
                spdm_context->connection_info.multi_key_conn_req = true;
            }
        }
    } else {
        spdm_context->connection_info.algorithm.dhe_named_group = 0;
        spdm_context->connection_info.algorithm.aead_cipher_suite = 0;
        spdm_context->connection_info.algorithm.req_base_asym_alg = 0;
        spdm_context->connection_info.algorithm.key_schedule = 0;
        spdm_context->connection_info.algorithm.other_params_support = 0;
        spdm_context->connection_info.algorithm.req_pqc_asym_alg = 0;
        spdm_context->connection_info.algorithm.kem_alg = 0;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "base_hash - 0x%08x\n",
                   spdm_context->connection_info.algorithm.base_hash_algo));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "base_asym - 0x%08x\n",
                   spdm_context->connection_info.algorithm.base_asym_algo));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dhe - 0x%04x\n",
                   spdm_context->connection_info.algorithm.dhe_named_group));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aead - 0x%04x\n",
                   spdm_context->connection_info.algorithm.aead_cipher_suite));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "req_asym - 0x%04x\n",
                   spdm_context->connection_info.algorithm.req_base_asym_alg));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "pqc_asym - 0x%08x\n",
                   spdm_context->connection_info.algorithm.pqc_asym_algo));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "req_pqc_asym - 0x%04x\n",
                   spdm_context->connection_info.algorithm.req_pqc_asym_alg));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "kem - 0x%04x\n",
                   spdm_context->connection_info.algorithm.kem_alg));

    /* -=[Update State Phase]=- */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_negotiate_algorithms(libspdm_context_t *spdm_context)
{
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    spdm_context->crypto_request = false;
    retry = spdm_context->retry_times;
    retry_delay_time = spdm_context->retry_delay_time;
    do {
        status = libspdm_try_negotiate_algorithms(spdm_context);
        if (status != LIBSPDM_STATUS_BUSY_PEER) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}
