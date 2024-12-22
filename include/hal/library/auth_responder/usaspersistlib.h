/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef AUTH_RESPONDER_USAS_PERSIST_LIB_H
#define AUTH_RESPONDER_USAS_PERSIST_LIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm_authorization.h"

/**
 * USAS state persisted between END_AUTH and a subsequent START_AUTH(Continue).
 * Both the Authorization target and Authorization initiator are required to
 * persist this information (DSP0289 sec. 10.5.2 "USAS continuation").
 *
 * @note persist_method uses the SPDM_AUTH_END_AUTH_ATTRIBUTES_PERSIST_METHOD_*
 *       values defined in spdm_authorization.h.
 **/
typedef struct {
    uint8_t  requester_nonce[SPDM_AUTH_NONCE_SIZE];
    uint8_t  responder_nonce[SPDM_AUTH_NONCE_SIZE];
    uint32_t saved_sequence_number; /* sequence number to resume from */
    uint8_t  persist_method;        /* 1=until reset, 2=permanent */
} spdm_auth_usas_saved_state_t;

/**
 * Check whether a saved USAS exists for the given Credential ID.
 *
 * @param  spdm_context    SPDM context.
 * @param  session_id      Session ID.
 * @param  credential_id   Credential ID to query.
 *
 * @return  true if a saved USAS exists for credential_id.
 **/
extern bool libspdm_auth_device_has_saved_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

/**
 * Load a saved USAS state for the given Credential ID.
 *
 * @param  spdm_context    SPDM context.
 * @param  session_id      Session ID.
 * @param  credential_id   Credential ID.
 * @param  state           Output: the saved USAS state.
 *
 * @return  true on success, false if no saved USAS exists.
 **/
extern bool libspdm_auth_device_load_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id,
    spdm_auth_usas_saved_state_t *state);

/**
 * Save USAS state for the given Credential ID.
 *
 * @param  spdm_context    SPDM context.
 * @param  session_id      Session ID.
 * @param  credential_id   Credential ID.
 * @param  state           USAS state to persist.
 *
 * @return  true on success.
 **/
extern bool libspdm_auth_device_save_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id,
    const spdm_auth_usas_saved_state_t *state);

/**
 * Clear (erase) the saved USAS state for the given Credential ID.
 *
 * @param  spdm_context    SPDM context.
 * @param  session_id      Session ID.
 * @param  credential_id   Credential ID.
 **/
extern void libspdm_auth_device_clear_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id);

#endif /* AUTH_RESPONDER_USAS_PERSIST_LIB_H */
