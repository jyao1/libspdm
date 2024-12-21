/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_AUTH_RESPONDER_LIB_INTERNAL_H
#define SPDM_AUTH_RESPONDER_LIB_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "internal/libspdm_responder_lib.h"
#include "library/spdm_auth_responder_lib.h"
#include "hal/library/auth_responder/authcapabilitieslib.h"
#include "hal/library/auth_responder/credidparamlib.h"
#include "hal/library/auth_responder/authpolicylib.h"
#include "hal/library/auth_responder/ownershiplib.h"
#include "hal/library/auth_responder/resettodefaultlib.h"
#include "hal/library/auth_responder/asymverifylib.h"

typedef
libspdm_return_t (*libspdm_auth_get_response_func_t) (
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_auth_version(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_select_auth_version_rsp(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_auth_capabilities(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_set_cred_id_params_done(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_cred_id_params(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_set_auth_policy_done(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_auth_policy(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_auth_processes(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_process_killed(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_start_auth_rsp(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_end_auth_rsp(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_privilege_elevated(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_elevated_privilege_ended(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_ownership_taken(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_get_response_auth_defaults_applied(
    libspdm_context_t *spdm_context,
    uint32_t session_id,
    bool has_auth,
    size_t request_size,
    const void *request,
    size_t *response_size,
    void *response);

libspdm_return_t libspdm_auth_generate_error_response(
    const void *spdm_context,
    uint8_t error_code,
    size_t *response_size,
    void *response);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_AUTH_RESPONDER_LIB_INTERNAL_H */
