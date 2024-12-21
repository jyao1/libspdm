/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_auth_requester_lib.h"

libspdm_return_t libspdm_auth_handle_simple_error_response(
    libspdm_context_t *spdm_context,
    uint8_t error_code)
{
    if (error_code == SPDM_AUTH_ERROR_CODE_BUSY) {
        return LIBSPDM_STATUS_BUSY_PEER;
    }

    if (error_code == SPDM_AUTH_ERROR_CODE_RESET_REQUIRED) {
        return LIBSPDM_STATUS_RESET_REQUIRED_PEER;
    }

    return LIBSPDM_STATUS_ERROR_PEER;
}
