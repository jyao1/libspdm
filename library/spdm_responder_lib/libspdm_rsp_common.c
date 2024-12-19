/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

uint16_t libspdm_allocate_rsp_session_id(const libspdm_context_t *spdm_context, bool use_psk)
{
    uint16_t rsp_session_id;
    const libspdm_session_info_t *session_info;
    size_t index;

    if (use_psk) {
        if ((spdm_context->max_psk_session_count != 0) &&
            (spdm_context->current_psk_session_count >= spdm_context->max_psk_session_count)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_allocate_req_session_id - MAX PSK session\n"));
            return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
        }
    } else {
        if ((spdm_context->max_dhe_session_count != 0) &&
            (spdm_context->current_dhe_session_count >= spdm_context->max_dhe_session_count)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_allocate_req_session_id - MAX DHE session\n"));
            return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
        }
    }

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((session_info[index].session_id & 0xFFFF0000) == (INVALID_SESSION_ID & 0xFFFF0000)) {
            rsp_session_id = (uint16_t)(0xFFFF - index);
            return rsp_session_id;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_allocate_rsp_session_id - MAX session_id\n"));
    return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
}

void libspdm_build_opaque_data_version_selection_element(
    const libspdm_context_t *spdm_context,
    size_t *data_out_size,
    void *data_out)
{
    size_t final_data_size;
    secured_message_opaque_element_table_header_t *opaque_element_table_header;
    secured_message_opaque_element_version_selection_t *opaque_element_version_section;
    void *end;

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        *data_out_size = 0;
        return;
    }

    final_data_size = libspdm_get_opaque_data_version_selection_element_size(spdm_context);
    LIBSPDM_ASSERT(*data_out_size >= final_data_size);

    opaque_element_table_header = data_out;
    opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
    opaque_element_table_header->vendor_len = 0;
    opaque_element_table_header->opaque_element_data_len =
        sizeof(secured_message_opaque_element_version_selection_t);

    opaque_element_version_section = (void *)(opaque_element_table_header + 1);
    opaque_element_version_section->sm_data_version =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
    opaque_element_version_section->sm_data_id =
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
    opaque_element_version_section->selected_version =
        spdm_context->connection_info.secured_message_version;
    /* Zero Padding*/
    end = opaque_element_version_section + 1;
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);
}

void libspdm_build_opaque_data_for_responder_exchange(
    libspdm_context_t *spdm_context,
    size_t *data_out_size,
    void *data_out)
{
    size_t final_data_size;
    size_t header_size;
    size_t version_selection_element_size;
    size_t invoke_seap_element_size;
    size_t auth_hello_element_size;
    uint8_t auth_role_mask;
    bool mut_auth_cap;
    uint8_t total_elements;

    auth_role_mask = spdm_context->local_context.auth.auth_role_mask;
    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        return;
    }

    mut_auth_cap = libspdm_is_capabilities_flag_supported(
        spdm_context, false,
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP);
    if (!mut_auth_cap) {
        auth_role_mask &= ~(LIBSPDM_AUTH_ROLE_SEAP_INITIATOR |
                            LIBSPDM_AUTH_ROLE_SEAP_TARGET);
    }
    if ((spdm_context->connection_info.auth.auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_TARGET) == 0) {
        auth_role_mask &= ~(LIBSPDM_AUTH_ROLE_SEAP_TARGET);
    }
    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_TARGET) != 0) {
        auth_role_mask &= ~(LIBSPDM_AUTH_ROLE_USAP_TARGET);
    }

    total_elements = 0;
    header_size = libspdm_get_opaque_data_table_header_size (spdm_context);
    if (spdm_context->local_context.secured_message_version.spdm_version_count != 0) {
        version_selection_element_size =
            libspdm_get_opaque_data_version_selection_element_size (spdm_context);
        total_elements++;
    } else {
        version_selection_element_size = 0;
    }
    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_INITIATOR) != 0) {
        invoke_seap_element_size = libspdm_get_aods_invoke_seap_element_size (spdm_context);
        total_elements++;
    } else {
        invoke_seap_element_size = 0;
    }
    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_USAP_TARGET) != 0) {
        auth_hello_element_size = libspdm_get_aods_auth_hello_element_size (spdm_context);
        total_elements++;
    } else {
        auth_hello_element_size = 0;
    }
    final_data_size = header_size + version_selection_element_size +
                      invoke_seap_element_size +
                      auth_hello_element_size;
    if (total_elements == 0) {
        *data_out_size = 0;
        return;
    }
    LIBSPDM_ASSERT(*data_out_size >= final_data_size);

    libspdm_build_opaque_data_table_header_data (spdm_context, total_elements, &header_size, data_out);
    data_out = (void *)((uint8_t *)data_out + header_size);
    if (spdm_context->local_context.secured_message_version.spdm_version_count != 0) {
        libspdm_build_opaque_data_version_selection_element (spdm_context, &version_selection_element_size, data_out);
        data_out = (void *)((uint8_t *)data_out + version_selection_element_size);
    }
    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_INITIATOR) != 0) {
        libspdm_build_aods_invoke_seap_element (spdm_context,
                                                spdm_context->local_context.auth.invoke_seap_credential_id,
                                                &invoke_seap_element_size, data_out);
        data_out = (void *)((uint8_t *)data_out + invoke_seap_element_size);
    }
    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_USAP_TARGET) != 0) {
        libspdm_build_aods_auth_hello_element (spdm_context, &auth_hello_element_size, data_out);
        data_out = (void *)((uint8_t *)data_out + auth_hello_element_size);
        spdm_context->connection_info.auth.auth_role_mask |= LIBSPDM_AUTH_ROLE_USAP_TARGET;
    }
    *data_out_size = final_data_size;
}

void libspdm_build_opaque_data_version_selection_data(libspdm_context_t *spdm_context,
                                                      size_t *data_out_size,
                                                      void *data_out)
{
    libspdm_build_opaque_data_for_responder_exchange (spdm_context, data_out_size, data_out);
}

libspdm_return_t
libspdm_process_opaque_data_supported_version_element(
    libspdm_context_t *spdm_context,
    size_t data_in_size,
    const void *data_in)
{
    const secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    const secured_message_opaque_element_supported_version_t
    *opaque_element_support_version;
    const spdm_version_number_t *versions_list;
    spdm_version_number_t common_version;
    uint8_t version_count;

    bool result;
    const void *get_element_ptr;
    size_t get_element_len;

    result = false;
    get_element_ptr = NULL;

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (data_in_size <
        libspdm_get_untrusted_opaque_data_supported_version_data_size(spdm_context, 1)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    result = libspdm_get_element_from_opaque_data(
        spdm_context, data_in_size,
        data_in, SPDM_REGISTRY_ID_DMTF,
        SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION,
        &get_element_ptr, &get_element_len);
    if ((!result) || (get_element_ptr == NULL)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"get element error!\n"));
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    opaque_element_table_header = (const secured_message_opaque_element_table_header_t*)
                                  get_element_ptr;

    /*check for supported version data*/
    opaque_element_support_version = (const void *)(opaque_element_table_header + 1);

    if ((const uint8_t *)opaque_element_support_version +
        sizeof(secured_message_opaque_element_supported_version_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (opaque_element_support_version->version_count == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    version_count = opaque_element_support_version->version_count;

    if ((opaque_element_table_header->vendor_len != 0) ||
        (opaque_element_table_header->opaque_element_data_len !=
         sizeof(secured_message_opaque_element_supported_version_t) +
         sizeof(spdm_version_number_t) * version_count)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    versions_list = (const void *)(opaque_element_support_version + 1);

    if ((const uint8_t *)versions_list + sizeof(spdm_version_number_t) >
        (const uint8_t *)opaque_element_table_header + get_element_len) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    result = libspdm_negotiate_connection_version(
        &common_version,
        spdm_context->local_context.secured_message_version.spdm_version,
        spdm_context->local_context.secured_message_version.spdm_version_count,
        versions_list, version_count);
    if (!result) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    libspdm_copy_mem(&(spdm_context->connection_info.secured_message_version),
                     sizeof(spdm_context->connection_info.secured_message_version),
                     &(common_version),
                     sizeof(spdm_version_number_t));

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_opaque_data_for_responder_exchange(
    libspdm_context_t *spdm_context,
    size_t data_in_size,
    const void *data_in)
{
    uint8_t auth_role_mask;
    bool mut_auth_cap;

    if (spdm_context->local_context.secured_message_version.spdm_version_count == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    spdm_context->connection_info.auth.auth_role_mask = 0;
    auth_role_mask = spdm_context->local_context.auth.auth_role_mask;
    mut_auth_cap = libspdm_is_capabilities_flag_supported(
        spdm_context, false,
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP);
    if (!mut_auth_cap) {
        auth_role_mask &= ~(LIBSPDM_AUTH_ROLE_SEAP_INITIATOR |
                            LIBSPDM_AUTH_ROLE_SEAP_TARGET);
    }

    if (spdm_context->local_context.secured_message_version.spdm_version_count != 0) {
        libspdm_process_opaque_data_supported_version_element (spdm_context, data_in_size, data_in);
    }

    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_TARGET) != 0) {
        libspdm_process_aods_invoke_seap_element (spdm_context, data_in_size, data_in);
    }
    if ((auth_role_mask & LIBSPDM_AUTH_ROLE_USAP_INITIATOR) != 0) {
        libspdm_process_aods_auth_hello_element (spdm_context, data_in_size, data_in);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t
libspdm_process_opaque_data_supported_version_data(libspdm_context_t *spdm_context,
                                                   size_t data_in_size,
                                                   const void *data_in)
{
    return libspdm_process_opaque_data_for_responder_exchange(spdm_context, data_in_size, data_in);
}