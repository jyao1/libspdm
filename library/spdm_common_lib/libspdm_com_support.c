/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

#if LIBSPDM_DEBUG_PRINT_ENABLE
typedef struct {
    uint8_t code;
    const char *code_str;
} libspdm_code_str_struct_t;

const char *libspdm_get_code_str(uint8_t request_code)
{
    size_t index;

    static libspdm_code_str_struct_t code_str_struct[] = {
        /* SPDM response code (1.0) */
        { SPDM_DIGESTS, "SPDM_DIGESTS" },
        { SPDM_CERTIFICATE, "SPDM_CERTIFICATE" },
        { SPDM_CHALLENGE_AUTH, "SPDM_CHALLENGE_AUTH" },
        { SPDM_VERSION, "SPDM_VERSION" },
        { SPDM_MEASUREMENTS, "SPDM_MEASUREMENTS" },
        { SPDM_CAPABILITIES, "SPDM_CAPABILITIES" },
        { SPDM_ALGORITHMS, "SPDM_ALGORITHMS" },
        { SPDM_VENDOR_DEFINED_RESPONSE, "SPDM_VENDOR_DEFINED_RESPONSE" },
        { SPDM_ERROR, "SPDM_ERROR" },
        /* SPDM response code (1.1) */
        { SPDM_KEY_EXCHANGE_RSP, "SPDM_KEY_EXCHANGE_RSP" },
        { SPDM_FINISH_RSP, "SPDM_FINISH_RSP" },
        { SPDM_PSK_EXCHANGE_RSP, "SPDM_PSK_EXCHANGE_RSP" },
        { SPDM_PSK_FINISH_RSP, "SPDM_PSK_FINISH_RSP" },
        { SPDM_HEARTBEAT_ACK, "SPDM_HEARTBEAT_ACK" },
        { SPDM_KEY_UPDATE_ACK, "SPDM_KEY_UPDATE_ACK" },
        { SPDM_ENCAPSULATED_REQUEST, "SPDM_ENCAPSULATED_REQUEST" },
        { SPDM_ENCAPSULATED_RESPONSE_ACK, "SPDM_ENCAPSULATED_RESPONSE_ACK" },
        { SPDM_END_SESSION_ACK, "SPDM_END_SESSION_ACK" },
        /* SPDM response code (1.2) */
        { SPDM_CSR, "SPDM_CSR" },
        { SPDM_SET_CERTIFICATE_RSP, "SPDM_SET_CERTIFICATE_RSP" },
        { SPDM_CHUNK_SEND_ACK, "SPDM_CHUNK_SEND_ACK" },
        { SPDM_CHUNK_RESPONSE, "SPDM_CHUNK_RESPONSE" },
        /* SPDM response code (1.3 )*/
        { SPDM_SUPPORTED_EVENT_TYPES, "SPDM_SUPPORTED_EVENT_TYPES" },
        { SPDM_SUBSCRIBE_EVENT_TYPES_ACK, "SPDM_SUBSCRIBE_EVENT_TYPES_ACK" },
        { SPDM_MEASUREMENT_EXTENSION_LOG, "SPDM_MEASUREMENT_EXTENSION_LOG" },
        { SPDM_KEY_PAIR_INFO, "SPDM_KEY_PAIR_INFO" },
        { SPDM_SET_KEY_PAIR_INFO_ACK, "SPDM_SET_KEY_PAIR_INFO_ACK" },
        { SPDM_ENDPOINT_INFO, "SPDM_ENDPOINT_INFO" },
        /* SPDM request code (1.0) */
        { SPDM_GET_DIGESTS, "SPDM_GET_DIGESTS" },
        { SPDM_GET_CERTIFICATE, "SPDM_GET_CERTIFICATE" },
        { SPDM_CHALLENGE, "SPDM_CHALLENGE" },
        { SPDM_GET_VERSION, "SPDM_GET_VERSION" },
        { SPDM_GET_MEASUREMENTS, "SPDM_GET_MEASUREMENTS" },
        { SPDM_GET_CAPABILITIES, "SPDM_GET_CAPABILITIES" },
        { SPDM_NEGOTIATE_ALGORITHMS, "SPDM_NEGOTIATE_ALGORITHMS" },
        { SPDM_VENDOR_DEFINED_REQUEST, "SPDM_VENDOR_DEFINED_REQUEST" },
        { SPDM_RESPOND_IF_READY, "SPDM_RESPOND_IF_READY" },
        /* SPDM request code (1.1) */
        { SPDM_KEY_EXCHANGE, "SPDM_KEY_EXCHANGE" },
        { SPDM_FINISH, "SPDM_FINISH" },
        { SPDM_PSK_EXCHANGE, "SPDM_PSK_EXCHANGE" },
        { SPDM_PSK_FINISH, "SPDM_PSK_FINISH" },
        { SPDM_HEARTBEAT, "SPDM_HEARTBEAT" },
        { SPDM_KEY_UPDATE, "SPDM_KEY_UPDATE" },
        { SPDM_GET_ENCAPSULATED_REQUEST, "SPDM_GET_ENCAPSULATED_REQUEST" },
        { SPDM_DELIVER_ENCAPSULATED_RESPONSE, "SPDM_DELIVER_ENCAPSULATED_RESPONSE" },
        { SPDM_END_SESSION, "SPDM_END_SESSION" },
        /* SPDM request code (1.2) */
        { SPDM_GET_CSR, "SPDM_GET_CSR" },
        { SPDM_SET_CERTIFICATE, "SPDM_SET_CERTIFICATE" },
        { SPDM_CHUNK_SEND, "SPDM_CHUNK_SEND" },
        { SPDM_CHUNK_GET, "SPDM_CHUNK_GET" },
        /* SPDM request code (1.3) */
        { SPDM_GET_SUPPORTED_EVENT_TYPES, "SPDM_GET_SUPPORTED_EVENT_TYPES" },
        { SPDM_SUBSCRIBE_EVENT_TYPES, "SPDM_SUBSCRIBE_EVENT_TYPES" },
        { SPDM_GET_MEASUREMENT_EXTENSION_LOG, "SPDM_GET_MEASUREMENT_EXTENSION_LOG" },
        { SPDM_GET_KEY_PAIR_INFO, "SPDM_GET_KEY_PAIR_INFO" },
        { SPDM_GET_SUPPORTED_EVENT_TYPES, "SPDM_SET_KEY_PAIR_INFO" },
        { SPDM_GET_ENDPOINT_INFO, "SPDM_GET_ENDPOINT_INFO" },
    };

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(code_str_struct); index++) {
        if (request_code == code_str_struct[index].code) {
            return code_str_struct[index].code_str;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "msg code 0x%x not found!!!\n", request_code));

    return "<unknown>";
}

void libspdm_internal_dump_hex_str(const uint8_t *data, size_t size)
{
    size_t index;
    for (index = 0; index < size; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x", data[index]));
    }
}

void libspdm_internal_dump_data(const uint8_t *data, size_t size)
{
    size_t index;
    for (index = 0; index < size; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x ", data[index]));
    }
}

void libspdm_internal_dump_hex(const uint8_t *data, size_t size)
{
    size_t index;
    size_t count;
    size_t left;

    #define COLUMN_SIZE (16 * 2)

    count = size / COLUMN_SIZE;
    left = size % COLUMN_SIZE;
    for (index = 0; index < count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%04zx: ", index * COLUMN_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(data + index * COLUMN_SIZE, COLUMN_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    if (left != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%04zx: ", index * COLUMN_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(data + index * COLUMN_SIZE, left);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }
}
#endif /* LIBSPDM_DEBUG_PRINT_ENABLE */

/**
 * Reads a 24-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 24-bit value that may be unaligned.
 *
 * @return The 24-bit value read from buffer.
 **/
uint32_t libspdm_read_uint24(const uint8_t *buffer)
{
    return (uint32_t)(buffer[0] | buffer[1] << 8 | buffer[2] << 16);
}

/**
 * Writes a 24-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 24-bit value that may be unaligned.
 * @param  value   24-bit value to write to buffer.
 **/
void libspdm_write_uint24(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)(value & 0xFF);
    buffer[1] = (uint8_t)((value >> 8) & 0xFF);
    buffer[2] = (uint8_t)((value >> 16) & 0xFF);
}

/**
 * Reads a 16-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 16-bit value that may be unaligned.
 *
 * @return The 16-bit value read from buffer.
 **/
uint16_t libspdm_read_uint16(const uint8_t *buffer)
{
    return (uint16_t)(buffer[0] | buffer[1] << 8);
}

/**
 * Writes a 16-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 16-bit value that may be unaligned.
 * @param  value   16-bit value to write to buffer.
 **/
void libspdm_write_uint16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)(value & 0xFF);
    buffer[1] = (uint8_t)((value >> 8) & 0xFF);
}

/**
 * Reads a 32-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 32-bit value that may be unaligned.
 *
 * @return The 32-bit value read from buffer.
 **/
uint32_t libspdm_read_uint32(const uint8_t *buffer)
{
    return (uint32_t)(buffer[0] | buffer[1] << 8 | buffer[2] << 16 | buffer[3] << 24);
}

/**
 * Writes a 32-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 32-bit value that may be unaligned.
 * @param  value   32-bit value to write to buffer.
 **/
void libspdm_write_uint32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)(value & 0xFF);
    buffer[1] = (uint8_t)((value >> 8) & 0xFF);
    buffer[2] = (uint8_t)((value >> 16) & 0xFF);
    buffer[3] = (uint8_t)((value >> 24) & 0xFF);
}

/**
 * Reads a 64-bit value from memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 64-bit value that may be unaligned.
 *
 * @return The 64-bit value read from buffer.
 **/
uint64_t libspdm_read_uint64(const uint8_t *buffer)
{
    return (uint64_t)(buffer[0]) |
           ((uint64_t)(buffer[1]) << 8) |
           ((uint64_t)(buffer[2]) << 16) |
           ((uint64_t)(buffer[3]) << 24) |
           ((uint64_t)(buffer[4]) << 32) |
           ((uint64_t)(buffer[5]) << 40) |
           ((uint64_t)(buffer[6]) << 48) |
           ((uint64_t)(buffer[7]) << 56);
}

/**
 * Writes a 64-bit value to memory that may be unaligned.
 *
 * @param  buffer  The pointer to a 64-bit value that may be unaligned.
 * @param  value   64-bit value to write to buffer.
 **/
void libspdm_write_uint64(uint8_t *buffer, uint64_t value)
{
    buffer[0] = (uint8_t)(value & 0xFF);
    buffer[1] = (uint8_t)((value >> 8) & 0xFF);
    buffer[2] = (uint8_t)((value >> 16) & 0xFF);
    buffer[3] = (uint8_t)((value >> 24) & 0xFF);
    buffer[4] = (uint8_t)((value >> 32) & 0xFF);
    buffer[5] = (uint8_t)((value >> 40) & 0xFF);
    buffer[6] = (uint8_t)((value >> 48) & 0xFF);
    buffer[7] = (uint8_t)((value >> 56) & 0xFF);
}

libspdm_return_t libspdm_append_managed_buffer(void *m_buffer, const void *buffer,
                                               size_t buffer_size)
{
    libspdm_managed_buffer_t *managed_buffer;

    LIBSPDM_ASSERT(buffer != NULL);

    if (buffer_size == 0) {
        return LIBSPDM_STATUS_SUCCESS;
    }

    managed_buffer = m_buffer;

    LIBSPDM_ASSERT(buffer_size != 0);
    LIBSPDM_ASSERT(managed_buffer->max_buffer_size >= managed_buffer->buffer_size);

    if (buffer_size > managed_buffer->max_buffer_size - managed_buffer->buffer_size) {
        /* Do not LIBSPDM_ASSERT here, because command processor will append message from external.*/
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "libspdm_append_managed_buffer 0x%x fail, rest 0x%x only\n",
                       (uint32_t)buffer_size,
                       (uint32_t)(managed_buffer->max_buffer_size - managed_buffer->buffer_size)));
        return LIBSPDM_STATUS_BUFFER_FULL;
    }
    LIBSPDM_ASSERT(buffer_size <= managed_buffer->max_buffer_size - managed_buffer->buffer_size);

    libspdm_copy_mem((uint8_t *)(managed_buffer + 1) + managed_buffer->buffer_size,
                     buffer_size, buffer, buffer_size);
    managed_buffer->buffer_size += buffer_size;

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_reset_managed_buffer(void *m_buffer)
{
    libspdm_managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;
    managed_buffer->buffer_size = 0;

    libspdm_zero_mem(managed_buffer + 1, managed_buffer->max_buffer_size);
}

size_t libspdm_get_managed_buffer_size(void *m_buffer)
{
    libspdm_managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    return managed_buffer->buffer_size;
}

void *libspdm_get_managed_buffer(void *m_buffer)
{
    libspdm_managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;

    return (managed_buffer + 1);
}

void libspdm_init_managed_buffer(void *m_buffer, size_t max_buffer_size)
{
    libspdm_managed_buffer_t *managed_buffer;

    managed_buffer = m_buffer;
    managed_buffer->max_buffer_size = max_buffer_size;

    libspdm_reset_managed_buffer(m_buffer);
}

/**
 * byte3 - libspdm major version
 * byte2 - libspdm minor version
 * byte1 - libspdm patch version
 * byte0 - libspdm alpha
 *         (office release with tag: 0, release candidate with tag: 1, non official release: 0xFF)
 **/
uint32_t libspdm_module_version(void)
{
    return (LIBSPDM_MAJOR_VERSION << 24) |
           (LIBSPDM_MINOR_VERSION << 16) |
           (LIBSPDM_PATCH_VERSION << 8) |
           (LIBSPDM_ALPHA);
}

/*true: FIPS enabled, false: FIPS disabled*/
bool libspdm_get_fips_mode(void)
{
#if LIBSPDM_FIPS_MODE
    return true;
#else
    return false;
#endif
}

uint32_t libspdm_mask_capability_flags(libspdm_context_t *spdm_context,
                                       bool is_request_flags, uint32_t flags)
{
    switch (libspdm_get_connection_version(spdm_context)) {
    case SPDM_MESSAGE_VERSION_10:
        if (is_request_flags) {
            /* A 1.0 Requester does not have any capability flags. */
            return 0;
        } else {
            return (flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_10_MASK);
        }
    case SPDM_MESSAGE_VERSION_11:
        if (is_request_flags) {
            return (flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_11_MASK);
        } else {
            return (flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_11_MASK);
        }
    case SPDM_MESSAGE_VERSION_12:
        if (is_request_flags) {
            return (flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_12_MASK);
        } else {
            return (flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_12_MASK);
        }
    case SPDM_MESSAGE_VERSION_13:
        if (is_request_flags) {
            return (flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_13_MASK);
        } else {
            return (flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_13_MASK);
        }
    case SPDM_MESSAGE_VERSION_14:
        if (is_request_flags) {
            return (flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_14_MASK);
        } else {
            return (flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_14_MASK);
        }
    default:
        LIBSPDM_ASSERT(false);
        return 0;
    }
}

uint32_t libspdm_mask_base_hash_algo(libspdm_context_t *spdm_context, uint32_t base_hash_algo)
{
    const uint8_t spdm_version = libspdm_get_connection_version(spdm_context);

    if (spdm_version >= SPDM_MESSAGE_VERSION_12) {
        return (base_hash_algo & SPDM_ALGORITHMS_BASE_HASH_ALGO_12_MASK);
    } else {
        return (base_hash_algo & SPDM_ALGORITHMS_BASE_HASH_ALGO_10_MASK);
    }
}

uint32_t libspdm_mask_measurement_hash_algo(libspdm_context_t *spdm_context,
                                            uint32_t measurement_hash_algo)
{
    const uint8_t spdm_version = libspdm_get_connection_version(spdm_context);

    if (spdm_version >= SPDM_MESSAGE_VERSION_12) {
        return (measurement_hash_algo & SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_12_MASK);
    } else {
        return (measurement_hash_algo & SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_10_MASK);
    }
}

uint8_t libspdm_mask_measurement_specification(libspdm_context_t *spdm_context,
                                               uint8_t measurement_specification)
{
    return (measurement_specification & SPDM_MEASUREMENT_SPECIFICATION_10_MASK);
}

uint8_t libspdm_mask_mel_specification(libspdm_context_t *spdm_context, uint8_t mel_specification)
{
    LIBSPDM_ASSERT(libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_13);

    return (mel_specification & SPDM_MEL_SPECIFICATION_13_MASK);
}

uint32_t libspdm_mask_base_asym_algo(libspdm_context_t *spdm_context, uint32_t base_asym_algo)
{
    const uint8_t spdm_version = libspdm_get_connection_version(spdm_context);

    if (spdm_version >= SPDM_MESSAGE_VERSION_12) {
        return (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_12_MASK);
    } else {
        return (base_asym_algo & SPDM_ALGORITHMS_BASE_ASYM_ALGO_10_MASK);
    }
}

uint16_t libspdm_mask_alg_supported(libspdm_context_t *spdm_context, uint8_t alg_type,
                                    uint16_t alg_supported)
{
    const uint8_t spdm_version = libspdm_get_connection_version(spdm_context);

    LIBSPDM_ASSERT(spdm_version >= SPDM_MESSAGE_VERSION_11);

    switch (alg_type) {
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        if (spdm_version >= SPDM_MESSAGE_VERSION_12) {
            return (alg_supported & SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_DHE_12_MASK);
        } else {
            return (alg_supported & SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_DHE_11_MASK);
        }
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        if (spdm_version >= SPDM_MESSAGE_VERSION_12) {
            return (alg_supported & SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_AEAD_12_MASK);
        } else {
            return (alg_supported & SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_AEAD_11_MASK);
        }
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        if (spdm_version >= SPDM_MESSAGE_VERSION_12) {
            return (alg_supported &
                    SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_REQ_BASE_ASYM_ALG_12_MASK);
        } else {
            return (alg_supported &
                    SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_REQ_BASE_ASYM_ALG_11_MASK);
        }
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
        return (alg_supported & SPDM_NEGOTIATE_ALGORITHMS_ALG_SUPPORTED_KEY_SCHEDULE_11_MASK);
    default:
        LIBSPDM_ASSERT(false);
        return 0;
    }
}

bool libspdm_validate_svh_vendor_id_len(uint8_t id, uint8_t vendor_id_len)
{
    switch (id) {
    case SPDM_REGISTRY_ID_DMTF:
    case SPDM_REGISTRY_ID_VESA:
        return (vendor_id_len == 0);
    case SPDM_REGISTRY_ID_TCG:
    case SPDM_REGISTRY_ID_USB:
    case SPDM_REGISTRY_ID_PCISIG:
    case SPDM_REGISTRY_ID_MIPI:
    case SPDM_REGISTRY_ID_CXL:
    case SPDM_REGISTRY_ID_JEDEC:
        return ((vendor_id_len == 0) || (vendor_id_len == 2));
    case SPDM_REGISTRY_ID_IANA:
    case SPDM_REGISTRY_ID_HDBASET:
        return ((vendor_id_len == 0) || (vendor_id_len == 4));
    case SPDM_REGISTRY_ID_IANA_CBOR:
        return true;
    default:
        return false;
    }
}
