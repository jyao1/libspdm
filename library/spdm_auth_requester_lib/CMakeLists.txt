cmake_minimum_required(VERSION 3.5)

add_library(spdm_auth_requester_lib STATIC "")

target_include_directories(spdm_auth_requester_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_auth_requester_lib
    PRIVATE
        libspdm_auth_req_get_auth_version.c
        libspdm_auth_req_select_auth_version.c
        libspdm_auth_req_get_auth_capabilities.c
        libspdm_auth_req_set_cred_id_params.c
        libspdm_auth_req_get_cred_id_params.c
        libspdm_auth_req_set_auth_policy.c
        libspdm_auth_req_get_auth_policy.c
        libspdm_auth_req_get_auth_processes.c
        libspdm_auth_req_kill_auth_process.c
        libspdm_auth_req_start_auth.c
        libspdm_auth_req_end_auth.c
        libspdm_auth_req_elevate_privilege.c
        libspdm_auth_req_end_elevated_privilege.c
        libspdm_auth_req_take_ownership.c
        libspdm_auth_req_auth_reset_to_default.c
        libspdm_auth_req_handle_error_response.c
        libspdm_auth_req_send_receive.c
)