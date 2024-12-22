/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_REQUESTER_ASYMSIGNLIB_H
#define AUTH_REQUESTER_ASYMSIGNLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_authorization.h"

extern bool libspdm_auth_device_get_algo_from_credential_id(
    void *spdm_context,
    uint32_t session_id,
    uint16_t credential_id,
    uint64_t *auth_base_algo,
    uint64_t *auth_base_hash_algo
    );

extern bool libspdm_auth_device_requester_data_sign(
    void *spdm_context, uint32_t session_id,
    uint16_t credential_id,
    spdm_auth_version_number_t spdm_auth_version,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size);

#endif /* AUTH_REQUESTER_ASYMSIGNLIB_H */
