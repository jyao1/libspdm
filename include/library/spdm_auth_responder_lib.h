/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_AUTH_RESPONDER_LIB_H
#define SPDM_AUTH_RESPONDER_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "library/spdm_common_lib.h"

libspdm_return_t libspdm_auth_get_response_vendor_defined_request(
    void *spdm_context,
    uint32_t session_id,
    const void *request,
    size_t request_size,
    void *response,
    size_t *response_size);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_AUTH_RESPONDER_LIB_H */
