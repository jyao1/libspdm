/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

size_t libspdm_get_aods_invoke_seap_element_size(const libspdm_context_t *spdm_context)
{
    size_t size;

    size = sizeof(spdm_auth_aods_table_header_t) +
           sizeof(spdm_auth_aods_invoke_seap_t);
    /* Add Padding*/
    return (size + 3) & ~3;
}

size_t libspdm_get_aods_seap_success_element_size(const libspdm_context_t *spdm_context)
{
    size_t size;

    size = sizeof(spdm_auth_aods_table_header_t) +
           sizeof(spdm_auth_aods_seap_success_t);
    /* Add Padding*/
    return (size + 3) & ~3;
}

size_t libspdm_get_aods_auth_hello_element_size(const libspdm_context_t *spdm_context)
{
    size_t size;

    size = sizeof(spdm_auth_aods_table_header_t) +
           sizeof(spdm_auth_aods_auth_hello_t);
    /* Add Padding*/
    return (size + 3) & ~3;
}

void libspdm_build_aods_invoke_seap_element(const libspdm_context_t *spdm_context,
                                            uint16_t credential_id,
                                            size_t *data_out_size,
                                            void *data_out)
{
    size_t final_data_size;
    spdm_auth_aods_table_header_t *aods_table_header;
    spdm_auth_aods_invoke_seap_t *aods_invoke_seap;
    void *end;

    final_data_size = libspdm_get_aods_invoke_seap_element_size(spdm_context);
    LIBSPDM_ASSERT(*data_out_size >= final_data_size);

    aods_table_header = (void *)(data_out);
    aods_table_header->id = SPDM_REGISTRY_ID_DMTF_DSP;
    aods_table_header->vendor_id_len = 2;
    aods_table_header->dmtf_spec_id = 289;
    aods_table_header->opaque_element_data_len = sizeof(spdm_auth_aods_invoke_seap_t);

    aods_invoke_seap = (void *)(aods_table_header + 1);
    aods_invoke_seap->aods_id = SPDM_AUTH_AODS_ID_INVOKE_SEAP;
    aods_invoke_seap->presence_extension = 0;
    aods_invoke_seap->credential_id = credential_id;
    end = (aods_invoke_seap + 1);

    /* Zero Padding. *data_out_size does not need to be changed, because data is 0 padded */
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);
}

void libspdm_build_aods_seap_success_element(const libspdm_context_t *spdm_context,
                                             size_t *data_out_size,
                                             void *data_out)
{
    size_t final_data_size;
    spdm_auth_aods_table_header_t *aods_table_header;
    spdm_auth_aods_seap_success_t *aods_seap_success;
    void *end;

    final_data_size = libspdm_get_aods_seap_success_element_size(spdm_context);
    LIBSPDM_ASSERT(*data_out_size >= final_data_size);

    aods_table_header = (void *)(data_out);
    aods_table_header->id = SPDM_REGISTRY_ID_DMTF_DSP;
    aods_table_header->vendor_id_len = 2;
    aods_table_header->dmtf_spec_id = 289;
    aods_table_header->opaque_element_data_len = sizeof(spdm_auth_aods_seap_success_t);

    aods_seap_success = (void *)(aods_table_header + 1);
    aods_seap_success->aods_id = SPDM_AUTH_AODS_ID_SEAP_SUCCESS;
    aods_seap_success->presence_extension = 0;
    end = (aods_seap_success + 1);

    /* Zero Padding. *data_out_size does not need to be changed, because data is 0 padded */
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);
}

void libspdm_build_aods_auth_hello_element(const libspdm_context_t *spdm_context,
                                           size_t *data_out_size,
                                           void *data_out)
{
    size_t final_data_size;
    spdm_auth_aods_table_header_t *aods_table_header;
    spdm_auth_aods_auth_hello_t *aods_auth_hello;
    void *end;

    final_data_size = libspdm_get_aods_auth_hello_element_size(spdm_context);
    LIBSPDM_ASSERT(*data_out_size >= final_data_size);

    aods_table_header = (void *)(data_out);
    aods_table_header->id = SPDM_REGISTRY_ID_DMTF_DSP;
    aods_table_header->vendor_id_len = 2;
    aods_table_header->dmtf_spec_id = 289;
    aods_table_header->opaque_element_data_len = sizeof(spdm_auth_aods_auth_hello_t);

    aods_auth_hello = (void *)(aods_table_header + 1);
    aods_auth_hello->aods_id = SPDM_AUTH_AODS_ID_AUTH_HELLO;
    aods_auth_hello->presence_extension = 0;
    end = (aods_auth_hello + 1);

    /* Zero Padding. *data_out_size does not need to be changed, because data is 0 padded */
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);
}

/**
 * Get element from multi element opaque data by element id.
 *
 * This function should be called in
 * libspdm_process_opaque_data_supported_version_data/libspdm_process_opaque_data_version_selection_data.
 *
 * @param[in]  data_in_size                size of multi element opaque data.
 * @param[in]  data_in                     A pointer to the multi element opaque data.
 * @param[in]  element_id                  element id.
 * @param[in]  vendor_id                   vendor_id for element id.
 * @param[in]  aods_id                     aods_id to identify for the AODS data type.
 * @param[out] get_element_ptr             pointer to store found element
 *
 * @retval true                            get element successfully
 * @retval false                           get element failed
 **/
bool libspdm_auth_get_element_from_opaque_data(libspdm_context_t *spdm_context,
                                               size_t data_in_size, const void *data_in,
                                               uint8_t element_id, uint16_t vendor_id,
                                               uint8_t aods_id,
                                               const void **get_element_ptr,
                                               size_t *get_element_len)
{
    const secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    const spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    const opaque_element_table_header_t
    *opaque_element_table_header;
    uint16_t opaque_element_data_len;
    const spdm_auth_aods_table_header_t
    *aods_element_table_header;
    const spdm_auth_aods_header_t
    *aods_element_header;

    bool result;
    uint8_t element_num;
    uint8_t element_index;
    size_t data_element_size;
    size_t current_element_len;
    size_t total_element_len;

    total_element_len = 0;
    result = false;

    /*check parameter in*/
    if (element_id > SPDM_REGISTRY_ID_MAX) {
        return false;
    }
    if ((data_in_size == 0) || (data_in == NULL)) {
        return false;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_in;
        if (data_in_size < sizeof(spdm_general_opaque_data_table_header_t)) {
            return false;
        }
        if (spdm_general_opaque_data_table_header->total_elements < 1) {
            return false;
        }
        opaque_element_table_header = (const void *)(spdm_general_opaque_data_table_header + 1);

        element_num = spdm_general_opaque_data_table_header->total_elements;

        data_element_size = data_in_size - sizeof(spdm_general_opaque_data_table_header_t);
    } else {
        general_opaque_data_table_header = data_in;
        if (data_in_size < sizeof(secured_message_general_opaque_data_table_header_t)) {
            return false;
        }
        if ((general_opaque_data_table_header->spec_id !=
             SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
            (general_opaque_data_table_header->opaque_version !=
             SECURED_MESSAGE_OPAQUE_VERSION) ||
            (general_opaque_data_table_header->total_elements < 1)) {
            return false;
        }
        opaque_element_table_header = (const void *)(general_opaque_data_table_header + 1);

        element_num = general_opaque_data_table_header->total_elements;

        data_element_size = data_in_size -
                            sizeof(secured_message_general_opaque_data_table_header_t);
    }

    for (element_index = 0; element_index < element_num; element_index++) {
        /*ensure the opaque_element_table_header is valid*/
        if (total_element_len + sizeof(opaque_element_table_header_t) >
            data_element_size) {
            return false;
        }

        /*check element header id*/
        if ((opaque_element_table_header->id > SPDM_REGISTRY_ID_MAX)) {
            return false;
        }

        if (total_element_len + sizeof(opaque_element_table_header_t) +
            opaque_element_table_header->vendor_len + sizeof(uint16_t) >
            data_element_size) {
            return false;
        }

        opaque_element_data_len = libspdm_read_uint16(
            (const uint8_t *)opaque_element_table_header +
            sizeof(opaque_element_table_header_t) +
            opaque_element_table_header->vendor_len);

        current_element_len = sizeof(opaque_element_table_header_t) +
                              opaque_element_table_header->vendor_len +
                              sizeof(uint16_t) + opaque_element_data_len;
        /* Add Padding*/
        current_element_len = (current_element_len + 3) & ~3;

        total_element_len += current_element_len;

        if (data_element_size < total_element_len) {
            return false;
        }

        if (opaque_element_table_header->id == element_id) {
            aods_element_table_header = (const void *)opaque_element_table_header;
            if ((aods_element_table_header->vendor_id_len == sizeof(uint16_t)) &&
                (aods_element_table_header->dmtf_spec_id == vendor_id)) {
                aods_element_header = (const void *)(aods_element_table_header + 1);
                if ((const uint8_t *)aods_element_header +
                    sizeof(spdm_auth_aods_header_t) >
                    (const uint8_t *)data_in + data_in_size) {
                    return false;
                }

                if (aods_element_header->aods_id == aods_id) {
                    /*get element by element id*/
                    *get_element_ptr = opaque_element_table_header;
                    *get_element_len = current_element_len;
                    result = true;
                }
            }
        }

        /*move to next element*/
        opaque_element_table_header = (const opaque_element_table_header_t *)
                                      ((const uint8_t *)opaque_element_table_header +
                                       current_element_len);
    }

    /*ensure data size is right*/
    if (data_element_size != total_element_len) {
        return false;
    }

    return result;
}

libspdm_return_t libspdm_process_aods_invoke_seap_element(
    libspdm_context_t *spdm_context,
    size_t data_in_size,
    const void *data_in)
{
    const void *get_element_ptr;
    size_t get_element_len;
    bool res;
    const spdm_auth_aods_invoke_seap_t *invoke_seap;
    const spdm_auth_aods_table_header_t *aods_element_table_header;

    res = libspdm_auth_get_element_from_opaque_data(
              spdm_context,
              data_in_size, data_in,
              SPDM_REGISTRY_ID_DMTF_DSP, 289,
              SPDM_AUTH_AODS_ID_INVOKE_SEAP,
              &get_element_ptr, &get_element_len
              );
    if (!res) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (get_element_len < (sizeof(spdm_auth_aods_table_header_t) + sizeof(spdm_auth_aods_invoke_seap_t))) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    aods_element_table_header = (const void *)get_element_ptr;
    invoke_seap = (const void *)(aods_element_table_header + 1);
    if ((spdm_context->local_context.auth.auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_TARGET) != 0) {
        spdm_context->connection_info.auth.auth_role_mask |= LIBSPDM_AUTH_ROLE_SEAP_TARGET;
        spdm_context->connection_info.auth.invoke_seap_credential_id = invoke_seap->credential_id;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_aods_seap_success_element(
    libspdm_context_t *spdm_context,
    size_t data_in_size,
    const void *data_in)
{
    const void *get_element_ptr;
    size_t get_element_len;
    bool res;

    res = libspdm_auth_get_element_from_opaque_data(
              spdm_context,
              data_in_size, data_in,
              SPDM_REGISTRY_ID_DMTF_DSP, 289,
              SPDM_AUTH_AODS_ID_SEAP_SUCCESS,
              &get_element_ptr, &get_element_len
              );
    if (!res) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if ((spdm_context->local_context.auth.auth_role_mask & LIBSPDM_AUTH_ROLE_SEAP_INITIATOR) != 0) {
        spdm_context->connection_info.auth.auth_role_mask |= LIBSPDM_AUTH_ROLE_SEAP_INITIATOR;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_aods_auth_hello_element(
    libspdm_context_t *spdm_context,
    size_t data_in_size,
    const void *data_in)
{
    const void *get_element_ptr;
    size_t get_element_len;
    bool res;

    res = libspdm_auth_get_element_from_opaque_data(
              spdm_context,
              data_in_size, data_in,
              SPDM_REGISTRY_ID_DMTF_DSP, 289,
              SPDM_AUTH_AODS_ID_AUTH_HELLO,
              &get_element_ptr, &get_element_len
              );
    if (!res) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if ((spdm_context->local_context.auth.auth_role_mask & LIBSPDM_AUTH_ROLE_USAP_INITIATOR) != 0) {
        spdm_context->connection_info.auth.auth_role_mask |= LIBSPDM_AUTH_ROLE_USAP_INITIATOR;
    }
    return LIBSPDM_STATUS_SUCCESS;
}
