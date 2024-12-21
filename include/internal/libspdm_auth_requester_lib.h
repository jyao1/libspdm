/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_AUTH_REQUESTER_LIB_INTERNAL_H
#define SPDM_AUTH_REQUESTER_LIB_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "internal/libspdm_requester_lib.h"
#include "library/spdm_auth_requester_lib.h"
#include "hal/library/auth_requester/asymsignlib.h"

libspdm_return_t libspdm_auth_handle_simple_error_response(
    libspdm_context_t *spdm_context,
    uint8_t error_code);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_AUTH_REQUESTER_LIB_INTERNAL_H */
