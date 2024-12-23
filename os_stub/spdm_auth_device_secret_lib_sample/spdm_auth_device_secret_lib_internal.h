/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_AUTH_DEVICE_SECRET_LIB_INTERNAL_H__
#define __SPDM_AUTH_DEVICE_SECRET_LIB_INTERNAL_H__

#include "library/spdm_crypt_lib.h"
#include "library/spdm_common_lib.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"
#include "hal/library/auth_responder/authcapabilitieslib.h"
#include "hal/library/auth_responder/authpolicylib.h"
#include "hal/library/auth_responder/credidparamlib.h"
#include "hal/library/auth_responder/ownershiplib.h"
#include "hal/library/auth_responder/resettodefaultlib.h"
#include "hal/library/auth_responder/asymverifylib.h"
#include "hal/library/auth_requester/asymsignlib.h"
#include "hal/library/debuglib.h"
#include "hal/library/cryptlib.h"

#define LIBSPDM_AUTH_DEVICE_INVALID_INDEX ((size_t)(-1))

bool libspdm_auth_device_reset_to_default_auth_policy(
    void *spdm_context,
    uint32_t session_id,
    bool reset_locked,
    uint16_t credential_id,
    uint16_t sv_reset_data_type_count,
    size_t sv_reset_data_type_list_size,
    const void *sv_reset_data_type_list
    );

bool libspdm_auth_device_reset_to_default_cred_id_params(
    void *spdm_context,
    uint32_t session_id,
    bool reset_locked,
    uint16_t credential_id,
    uint16_t sv_reset_data_type_count,
    size_t sv_reset_data_type_list_size,
    const void *sv_reset_data_type_list
    );

void libspdm_auth_device_revoke_ownership(
    void *spdm_context,
    uint32_t session_id
    );

uint64_t libspdm_auth_device_get_allowed_auth_base_asym_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint64_t libspdm_auth_device_get_allowed_auth_base_hash_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint16_t libspdm_auth_device_get_credential_privileges(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint8_t libspdm_auth_device_get_auth_process_privileges(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint16_t libspdm_auth_device_get_policy_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

bool libspdm_auth_device_lock_policy_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

bool libspdm_auth_device_unlock_policy_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint64_t libspdm_auth_device_get_auth_base_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint64_t libspdm_auth_device_get_auth_base_hash_algo(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

uint16_t libspdm_auth_device_get_credential_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

bool libspdm_auth_device_lock_credential_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

bool libspdm_auth_device_unlock_credential_attributes(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

#endif
