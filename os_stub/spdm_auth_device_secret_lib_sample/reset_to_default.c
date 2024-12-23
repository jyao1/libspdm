/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_auth_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

bool libspdm_auth_device_reset_to_default(
    void *spdm_context,
    uint32_t session_id,
    uint16_t data_type,
    uint16_t credential_id,
    uint16_t sv_reset_data_type_count,
    size_t sv_reset_data_type_list_size,
    const void *sv_reset_data_type_list,
    bool *reset_required
    )
{
    bool reset_locked;

    *reset_required = false;
    data_type &= SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_MASK;
    if (data_type == 0) {
        return false;
    }
    if ((credential_id == SPDM_AUTH_CREDENTIAL_ID_ALL) &&
        (data_type == SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_MASK)) {
        reset_locked = true;
        libspdm_auth_device_reset_to_default_auth_policy (
            spdm_context, session_id, reset_locked, credential_id,
            sv_reset_data_type_count, sv_reset_data_type_list_size, sv_reset_data_type_list
            );
        libspdm_auth_device_reset_to_default_cred_id_params (
            spdm_context, session_id, reset_locked, credential_id,
            sv_reset_data_type_count, sv_reset_data_type_list_size, sv_reset_data_type_list
            );
        libspdm_auth_device_revoke_ownership(spdm_context, session_id);
        *reset_required = true;
        return true;
    }

    reset_locked = false;
    if ((data_type & SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_CRED_ID_PARAMS) != 0) {
        return libspdm_auth_device_reset_to_default_cred_id_params (
            spdm_context, session_id, reset_locked, credential_id,
            sv_reset_data_type_count, sv_reset_data_type_list_size, sv_reset_data_type_list
            );
    }
    if ((data_type & SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_AUTH_POLICY) != 0) {
        return libspdm_auth_device_reset_to_default_auth_policy (
            spdm_context, session_id, reset_locked, credential_id,
            sv_reset_data_type_count, sv_reset_data_type_list_size, sv_reset_data_type_list
            );
    }
    LIBSPDM_ASSERT(false);
    return false;
}