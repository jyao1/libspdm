/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_auth_device_secret_lib_internal.h"

/*
 * Sample stub: single-slot in-memory USAS persistent storage.
 * Not truly persistent across power cycles; replace with real NV storage
 * in production.
 */
static bool     m_usas_saved          = false;
static uint16_t m_usas_credential_id  = 0;
static spdm_auth_usas_saved_state_t m_usas_saved_state;

bool libspdm_auth_device_has_saved_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    return m_usas_saved && (m_usas_credential_id == credential_id);
}

bool libspdm_auth_device_load_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id,
    spdm_auth_usas_saved_state_t *state)
{
    if (!m_usas_saved || (m_usas_credential_id != credential_id)) {
        return false;
    }
    *state = m_usas_saved_state;
    return true;
}

bool libspdm_auth_device_save_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id,
    const spdm_auth_usas_saved_state_t *state)
{
    m_usas_saved         = true;
    m_usas_credential_id = credential_id;
    m_usas_saved_state   = *state;
    return true;
}

void libspdm_auth_device_clear_usas(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    if (m_usas_credential_id == credential_id) {
        m_usas_saved         = false;
        m_usas_credential_id = 0;
    }
}
