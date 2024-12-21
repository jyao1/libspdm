/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

libspdm_return_t libspdm_auth_generate_error_response(
    const void *spdm_context,
    uint8_t error_code,
    size_t *response_size,
    void *response)
{
    spdm_auth_error_response_t *spdm_auth_response;

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_auth_error_response_t));
    *response_size = sizeof(spdm_auth_error_response_t);
    spdm_auth_response = response;

    spdm_auth_response->header.request_response_code = SPDM_AUTH_ERROR;
    spdm_auth_response->header.reserved = 0;
    spdm_auth_response->error_code = error_code;

    return LIBSPDM_STATUS_SUCCESS;
}
