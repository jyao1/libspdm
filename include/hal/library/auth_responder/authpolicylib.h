/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_RESPONDER_AUTH_POLICY_LIB_H
#define AUTH_RESPONDER_AUTH_POLICY_LIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_authorization.h"

extern bool libspdm_auth_device_set_auth_policy(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint8_t set_auth_policy_op,
    size_t policy_list_size,
    const void *policy_list,
    bool *operation_failed
    );

extern bool libspdm_auth_device_get_auth_policy(
    void *spdm_context,
    uint32_t session_id,
    bool has_auth,
    uint16_t credential_id,
    uint16_t *policy_attributes,
    size_t policy_list_size,
    void *policy_list,
    bool *operation_failed
    );

extern uint16_t libspdm_auth_device_get_credential_privileges(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

#endif /* AUTH_RESPONDER_AUTH_POLICY_LIB_H */
