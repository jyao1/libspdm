/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_RESPONDER_OWNERSHIP_LIB_H
#define AUTH_RESPONDER_OWNERSHIP_LIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_authorization.h"

extern bool libspdm_auth_device_take_ownership(
    void *spdm_context,
    uint32_t session_id
    );

#endif /* AUTH_RESPONDER_OWNERSHIP_LIB_H */
