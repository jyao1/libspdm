cmake_minimum_required(VERSION 3.5)

add_library(spdm_auth_responder_lib STATIC "")

target_include_directories(spdm_auth_responder_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_auth_responder_lib
    PRIVATE
        libspdm_auth_rsp_auth_version.c
        libspdm_auth_rsp_select_auth_version_rsp.c
        libspdm_auth_rsp_auth_capabilities.c
        libspdm_auth_rsp_set_cred_id_params_done.c
        libspdm_auth_rsp_cred_id_params.c
        libspdm_auth_rsp_set_auth_policy_done.c
        libspdm_auth_rsp_auth_policy.c
        libspdm_auth_rsp_auth_processes.c
        libspdm_auth_rsp_process_killed.c
        libspdm_auth_rsp_start_auth_rsp.c
        libspdm_auth_rsp_end_auth_rsp.c
        libspdm_auth_rsp_privilege_elevated.c
        libspdm_auth_rsp_elevated_privilege_ended.c
        libspdm_auth_rsp_ownership_taken.c
        libspdm_auth_rsp_auth_defaults_applied.c
        libspdm_auth_rsp_dispatch.c
        libspdm_auth_rsp_error.c
)