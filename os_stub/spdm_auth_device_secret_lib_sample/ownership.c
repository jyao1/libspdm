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

extern uint8_t m_device_provisioning_state;

void libspdm_auth_device_revoke_ownership(
    void *spdm_context,
    uint32_t session_id
    )
{
    m_device_provisioning_state = SPDM_AUTH_DEVICE_PROVISION_STATE_DEFAULT_STATE;
}

bool libspdm_auth_device_take_ownership(
    void *spdm_context,
    uint32_t session_id
    )
{
    if (m_device_provisioning_state == SPDM_AUTH_DEVICE_PROVISION_STATE_OWNED) {
        return false;
    }
    m_device_provisioning_state = SPDM_AUTH_DEVICE_PROVISION_STATE_OWNED;
    return true;
}
