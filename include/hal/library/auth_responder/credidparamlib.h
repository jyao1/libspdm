/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_RESPONDER_CRED_ID_PARAM_LIB_H
#define AUTH_RESPONDER_CRED_ID_PARAM_LIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_authorization.h"

extern bool libspdm_auth_device_set_cred_id_params(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint8_t set_cred_info_op,
    size_t cred_params_size,
    const void *cred_params,
    bool *operation_failed
    );

extern bool libspdm_auth_device_get_cred_id_params(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint16_t credential_id,
    uint16_t *cred_attributes,
    size_t cred_params_size,
    void *cred_params,
    bool *operation_failed
    );

#endif /* AUTH_RESPONDER_CRED_ID_PARAM_LIB_H */
