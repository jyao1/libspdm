/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_RESPONDER_AUTH_EVENT_LIB_H
#define AUTH_RESPONDER_AUTH_EVENT_LIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_authorization.h"

/**
 * Notify the device HAL that a SET_CRED_ID_PARAMS operation succeeded.
 *
 * The device HAL should queue a CredIDparamsChanged event (EventTypeId=1)
 * for delivery via the SPDM event mechanism.
 *
 * This function is required when AuthEventCap is set and the device supports
 * SET_CRED_ID_PARAMS (DSP0289 Table 73, Requirement=Conditional).
 *
 * @param  spdm_context    SPDM context.
 * @param  session_id      Session ID.
 * @param  credential_id   Credential ID whose parameters changed.
 **/
extern void libspdm_auth_device_notify_cred_id_params_changed(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

/**
 * Notify the device HAL that a SET_AUTH_POLICY operation succeeded for one
 * policy entry.  Called once per changed policy.
 *
 * The device HAL should queue an AuthPolicyChanged event (EventTypeId=2)
 * for delivery via the SPDM event mechanism.
 *
 * This function is required when AuthEventCap is set and the device supports
 * SET_AUTH_POLICY (DSP0289 Table 73, Requirement=Conditional).
 *
 * @param  spdm_context      SPDM context.
 * @param  session_id        Session ID.
 * @param  credential_id     Credential ID whose policy changed.
 * @param  policy_owner_id   SVH identifying the policy definition owner.
 * @param  policy_id_len     Length in bytes of policy_id.
 * @param  policy_id         Byte array identifying the specific policy.
 **/
extern void libspdm_auth_device_notify_auth_policy_changed(
    void *spdm_context, uint32_t session_id, uint16_t credential_id,
    const spdm_svh_dmtf_dsp_header_t *policy_owner_id,
    uint16_t policy_id_len, const uint8_t *policy_id);

#endif /* AUTH_RESPONDER_AUTH_EVENT_LIB_H */
