/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of DSP0289 Authorization Specification
 * version 1.0.0 in Distributed Management Task Force (DMTF).
 **/

#ifndef SPDM_AUTHORIZATION_H
#define SPDM_AUTHORIZATION_H

#pragma pack(1)

/* Authorization Credential Structure */
typedef struct {
    uint16_t credential_id;
    uint8_t credential_type;
    uint64_t auth_base_algo;
    uint64_t auth_base_hash_algo;
    uint32_t reserved;
    uint32_t credential_data_size;
    /* uint8_t credential_data[credential_data_size]; */
} spdm_auth_credential_struct_t;

#define SPDM_AUTH_MIN_CREDENTIAL_ID_COUNT 0x8
#define SPDM_AUTH_CREDENTIAL_ID_ALL 0xFFFF

/* Authorization Credential Type */
#define SPDM_AUTH_CREDENTIAL_TYPE_ASYMMETRIC_KEY 1

/* Authorization Base Algo */
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 0x00000001
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 0x00000002
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 0x00000004
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 0x00000008
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 0x00000010
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 0x00000020
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 0x00000040
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 0x00000080
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 0x00000100
#define SPDM_AUTH_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 0x00000200
#define SPDM_AUTH_BASE_ASYM_ALGO_EDDSA_ED25519 0x00000400
#define SPDM_AUTH_BASE_ASYM_ALGO_EDDSA_ED448 0x00000800

/* Authorization Base Hash Algo */
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_256 0x00000001
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_384 0x00000002
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA_512 0x00000004
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_256 0x00000008
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_384 0x00000010
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SHA3_512 0x00000020
#define SPDM_AUTH_BASE_HASH_ALGO_TPM_ALG_SM3_256 0x00000040

/* Authorization Policy List */
typedef struct {
    uint16_t credential_id;
    uint16_t num_of_policies;
    /* spdm_auth_policy_struct_for_dsp0289_t policies[num_of_policies]; */
} spdm_auth_policy_list_t;

/* DSP0289 General Policy */
typedef struct {
    uint64_t allowed_auth_base_asym_algo;
    uint64_t allowed_auth_base_hash_algo;
    uint16_t credential_privileges;
    uint8_t auth_process_privileges;
} spdm_auth_dsp0289_general_policy_t;

/* DSP0289 Authorization Policy Bits */
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_MODIFY_CREDENTIAL_INFO 0x1
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_QUERY_CREDENTIAL_INFO 0x2
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_GRANT_OTHER_POLICY 0x4
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_REVOKE_OTHER_POLICY 0x8
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_QUERY_POLICY 0x10
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_RESET_TO_DEFAULTS 0x20
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_LOCK_SELF 0x40
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_RETRIEVE_AUTH_PROC_LIST 0x80
#define SPDM_AUTH_POLICY_CREDENTIAL_PRIVILEGES_KILL_AUTH_PROC 0x100

/* DSP0289 Authorization Process Policy Bits */
#define SPDM_AUTH_POLICY_AUTH_PROCESS_PRIVILEGES_SEAP 0x1
#define SPDM_AUTH_POLICY_AUTH_PROCESS_PRIVILEGES_USAP 0x2
#define SPDM_AUTH_POLICY_AUTH_PROCESS_PRIVILEGES_PERSIST_USAP 0x2

/* DSP0289 Policy Structure */
typedef struct {
    uint16_t policy_type;
    uint16_t policy_len;
    spdm_auth_dsp0289_general_policy_t policy;
} spdm_auth_dsp0289_policy_struct_t;

/* DSP0289 Policy Types */
#define SPDM_AUTH_POLICY_TYPE_GENERAL_POLICY 1

/* Authorization Policy Structure */
typedef struct {
    spdm_svh_dmtf_dsp_header_t policy_owner_id;
    uint16_t policy_len;
    spdm_auth_dsp0289_policy_struct_t policy;
} spdm_auth_policy_struct_for_dsp0289_t;



#define SPDM_AUTH_NONCE_SIZE 32

/* Authorization Message header */
typedef struct {
    uint16_t credential_id;
    uint32_t sequence_number;
    uint8_t requester_nonce[SPDM_AUTH_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_AUTH_NONCE_SIZE];
} spdm_auth_record_sign_header_t;

#define SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT "dmtf-auth-v1.0.*"
#define SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT_SIZE \
    (sizeof(SPDM_AUTH_VERSION_1_0_SIGNING_PREFIX_CONTEXT) - 1)
#define SPDM_AUTH_VERSION_1_0_SIGNING_CONTEXT_SIZE 100

#define SPDM_AUTH_USAP_SIGN_CONTEXT "usap signing"
#define SPDM_AUTH_USAP_SIGN_CONTEXT_SIZE (sizeof(SPDM_AUTH_USAP_SIGN_CONTEXT) - 1)

/* Authorization message definition */

/* Authorization Message Request OpCode */
#define SPDM_AUTH_GET_AUTH_VERSION 0x81
#define SPDM_AUTH_SELECT_AUTH_VERSION 0x82
#define SPDM_AUTH_SET_CRED_ID_PARAMS 0x83
#define SPDM_AUTH_GET_CRED_ID_PARAMS 0x84
#define SPDM_AUTH_SET_AUTH_POLICY 0x85
#define SPDM_AUTH_GET_AUTH_POLICY 0x86
#define SPDM_AUTH_START_AUTH 0x87
#define SPDM_AUTH_END_AUTH 0x88
#define SPDM_AUTH_ELEVATE_PRIVILEGE 0x89
#define SPDM_AUTH_END_ELEVATED_PRIVILEGE 0x8a
#define SPDM_AUTH_GET_AUTH_CAPABILITIES 0x8b
#define SPDM_AUTH_AUTH_RESET_TO_DEFAULT 0x8c
#define SPDM_AUTH_TAKE_OWNERSHIP 0x8d
#define SPDM_AUTH_GET_AUTH_PROCESSES 0x8e
#define SPDM_AUTH_KILL_AUTH_PROCESS 0x8f

/* Authorization Message Response OpCode */
#define SPDM_AUTH_AUTH_VERSION 0x01
#define SPDM_AUTH_SELECT_AUTH_VERSION_RSP 0x02
#define SPDM_AUTH_SET_CRED_ID_PARAMS_DONE 0x03
#define SPDM_AUTH_CRED_ID_PARAMS 0x04
#define SPDM_AUTH_SET_AUTH_POLICY_DONE 0x05
#define SPDM_AUTH_AUTH_POLICY 0x06
#define SPDM_AUTH_START_AUTH_RSP 0x07
#define SPDM_AUTH_END_AUTH_RSP 0x08
#define SPDM_AUTH_PRIVILEGE_ELEVATED 0x09
#define SPDM_AUTH_ELEVATED_PRIVILEGE_ENDED 0x0a
#define SPDM_AUTH_AUTH_CAPABILITIES 0x0b
#define SPDM_AUTH_AUTH_DEFAULTS_APPLIED 0x0c
#define SPDM_AUTH_OWNERSHIP_TAKEN 0x0d
#define SPDM_AUTH_AUTH_PROCESSES 0x0e
#define SPDM_AUTH_PROCESS_KILLED 0x0f
#define SPDM_AUTH_ERROR 0x7f

/* Authorization Message Header */
typedef struct {
    uint8_t request_response_code;
    uint8_t reserved;
} spdm_auth_message_header_t;

/* Authorization ERROR response */
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t error_code;
    /* uint8_t error_data[]; */
} spdm_auth_error_response_t;

typedef struct {
    uint8_t error_code;
    /* uint8_t error_data[]; */
} spdm_auth_error_code_data_t;

#define SPDM_AUTH_ERROR_DATA_MAX_SIZE 32

/* Authorization error code */
#define SPDM_AUTH_ERROR_CODE_INVALID_REQUEST 0x01
#define SPDM_AUTH_ERROR_CODE_RESET_REQUIRED 0x02
#define SPDM_AUTH_ERROR_CODE_BUSY 0x03
#define SPDM_AUTH_ERROR_CODE_UNEXPECTED_REQUEST 0x04
#define SPDM_AUTH_ERROR_CODE_UNSPECIFIED 0x05
#define SPDM_AUTH_ERROR_CODE_ACCESS_DENIED 0x06
#define SPDM_AUTH_ERROR_CODE_OPERATION_FAILED 0x07
#define SPDM_AUTH_ERROR_CODE_VERSION_MISMATCH 0x08
#define SPDM_AUTH_ERROR_CODE_UNSUPPORTED_REQUEST 0x09

/* GET_AUTH_VERSION request */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_get_auth_version_request_t;

/* AUTH_VERSION response */
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    /* spdm_auth_version_number_t version_number_entry[version_number_entry_count]; */
} spdm_auth_auth_version_response_t;

#define SPDM_AUTH_MAX_VERSION_COUNT 1
#define SPDM_AUTH_VERSION_10 0x10

/* 
 * Auth VERSION structure
 * bit[15:12] major_version
 * bit[11:8]  minor_version
 * bit[7:4]   update_version_number
 * bit[3:0]   alpha
 */
typedef uint16_t spdm_auth_version_number_t;
#define SPDM_AUTH_VERSION_NUMBER_SHIFT_BIT 8

/* SELECT_AUTH_VERSION request */
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t auth_version;
} spdm_auth_select_auth_version_request_t;

/* SELECT_AUTH_VERSION_RSP response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_select_auth_version_rsp_response_t;

/* GET_AUTH_CAPABILITIES request */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_get_auth_capabilities_request_t;

/* AUTH_CAPABILITIES response */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t message_caps;
    uint16_t auth_process_caps;
    uint8_t device_provisioning_state;
    uint8_t auth_record_process_time;
    uint64_t auth_base_asym_algo_supported;
    uint64_t auth_base_hash_algo_supported;
    uint16_t supported_policy_owner_id_count;
    /* spdm_svh_dmtf_dsp_header_t supported_policy_owner_id_list[supported_policy_owner_id_count]; */
} spdm_auth_auth_capabilities_response_t;

/* Authorization Message Supported Bit */
#define SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_CRED_ID_PARAMS_CAP 0x1
#define SPDM_AUTH_MESSAGE_SUPPORTED_CHANGE_AUTH_POLICY_CAP 0x2
#define SPDM_AUTH_MESSAGE_SUPPORTED_AUTH_EVENT_CAP 0x4
#define SPDM_AUTH_MESSAGE_SUPPORTED_AUTH_PROC_LIST_CAP 0x8
#define SPDM_AUTH_MESSAGE_SUPPORTED_AUTH_PROC_KILL_CAP 0x10

/* Authorization Process Supported Bit */
#define SPDM_AUTH_PROCESS_SUPPORTED_USAP_CAP 0x1
#define SPDM_AUTH_PROCESS_SUPPORTED_SEAP_CAP 0x2
#define SPDM_AUTH_PROCESS_SUPPORTED_RESET_PERSIST_CAP 0x4
#define SPDM_AUTH_PROCESS_SUPPORTED_PERM_PERSIST_CAP 0x8

/* Device Provisioning State Values */
#define SPDM_AUTH_DEVICE_PROVISION_STATE_UNPROVISIONED 0
#define SPDM_AUTH_DEVICE_PROVISION_STATE_DEFAULT_STATE 1
#define SPDM_AUTH_DEVICE_PROVISION_STATE_OWNED 2

/* SET_CRED_ID_PARAMS request */
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t set_cred_info_op;
    spdm_auth_credential_struct_t cred_params;
} spdm_auth_set_cred_id_params_request_t;

/* Authorization SetCredInfoOp */
#define SPDM_AUTH_SET_CRED_INFO_OP_PARAMETER_CHANGE 1
#define SPDM_AUTH_SET_CRED_INFO_OP_LOCK 2
#define SPDM_AUTH_SET_CRED_INFO_OP_UNLOCK 3

/* SET_CRED_ID_PARAMS_DONE response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_set_cred_id_params_done_response_t;

/* GET_CRED_ID_PARAMS request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
} spdm_auth_get_cred_id_params_request_t;

/* CRED_ID_PARAMS response */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t cred_attributes;
    spdm_auth_credential_struct_t cred_params;
} spdm_auth_cred_id_params_response_t;

/* Authorization Credential Attributes bit */
#define SPDM_AUTH_CRED_ATTRIBUTES_LOCKABLE 0x1
#define SPDM_AUTH_CRED_ATTRIBUTES_UNLOCKABLE 0x2
#define SPDM_AUTH_CRED_ATTRIBUTES_LOCKED 0x4

/* SET_AUTH_POLICY request */
typedef struct {
    spdm_auth_message_header_t header;
    uint8_t set_auth_policy_op;
    spdm_auth_policy_list_t policy_list;
} spdm_auth_set_auth_policy_request_t;

/* Authorization SetAuthPolicyOp */
#define SPDM_AUTH_SET_AUTH_POLICY_OP_POLICY_CHANGE 1
#define SPDM_AUTH_SET_AUTH_POLICY_OP_LOCK 2
#define SPDM_AUTH_SET_AUTH_POLICY_OP_UNLOCK 3

/* SET_AUTH_POLICY_DONE response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_set_auth_policy_done_response_t;

/* GET_AUTH_POLICY request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
} spdm_auth_get_auth_policy_request_t;

/* AUTH_POLICY response */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t policy_attributes;
    spdm_auth_policy_list_t policy_list;
} spdm_auth_auth_policy_response_t;

/* GET_AUTH_PROCESSES request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
} spdm_auth_get_auth_processes_request_t;

/* AUTH_PROCESSES response */
typedef struct {
    uint8_t id[32];
} spdm_auth_auth_proc_id_t;

typedef struct {
    uint16_t credential_id;
    uint8_t auth_process_type;
    spdm_auth_auth_proc_id_t auth_proc_id;
} spdm_auth_auth_proc_info_t;

#define SPDM_AUTH_AUTH_PROC_TYPE_ACTIVE_USAS 0
#define SPDM_AUTH_AUTH_PROC_TYPE_ACTIVE_SEAS 1
#define SPDM_AUTH_AUTH_PROC_TYPE_SAVED_USAS 2

typedef struct {
    spdm_auth_message_header_t header;
    uint16_t auth_proc_info_count;
    /* spdm_auth_auth_proc_info_t auth_proc_info_list[auth_proc_info_count]; */
} spdm_auth_auth_processes_response_t;

/* KILL_AUTH_PROCESS request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
    spdm_auth_auth_proc_id_t auth_proc_id;
} spdm_auth_kill_auth_process_request_t;

/* PROCESS_KILLED response */
typedef struct {
    spdm_auth_message_header_t header;
    spdm_auth_auth_proc_id_t auth_proc_id;
} spdm_auth_process_killed_response_t;

/* START_AUTH request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
    uint8_t nonce_len;
    uint8_t nonce[SPDM_AUTH_NONCE_SIZE];
} spdm_auth_start_auth_request_t;

/* START_AUTH_RSP response */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
    uint8_t nonce_len;
    uint8_t nonce[SPDM_AUTH_NONCE_SIZE];
} spdm_auth_start_auth_rsp_response_t;

/* END_AUTH request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
} spdm_auth_end_auth_request_t;

/* END_AUTH_RSP response */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t credential_id;
} spdm_auth_end_auth_rsp_response_t;

/* ELEVATE_PRIVILEGE request */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_elevate_privilege_request_t;

/* PRIVILEGE_ELEVATED response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_privilege_elevated_response_t;

/* END_ELEVATED_PRIVILEGE request */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_end_elevated_privilege_request_t;

/* ELEVATED_PRIVILEGE_ENDED response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_elevated_privilege_ended_response_t;

/* TAKE_OWNERSHIP request */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_take_ownership_request_t;

/* OWNERSHIP_TAKEN response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_ownership_taken_response_t;

/* AUTH_RESET_TO_DEFAULT request */
typedef struct {
    spdm_auth_message_header_t header;
    uint16_t data_type;
    uint16_t credential_id;
    uint16_t sv_reset_data_type_count;
    /* sv_reset_data_type_t sv_reset_data_type_list[sv_reset_data_type_count] */
} spdm_auth_auth_reset_to_default_request_t;

/* Authorization reset_to_default Data Type Bit  */
#define SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_CRED_ID_PARAMS 0x1
#define SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_AUTH_POLICY 0x2
#define SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_MASK ( \
        SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_CRED_ID_PARAMS | \
        SPDM_AUTH_RESET_TO_DEFAULT_DATA_TYPE_AUTH_POLICY)

/* AUTH_DEFAULTS_APPLIED response */
typedef struct {
    spdm_auth_message_header_t header;
} spdm_auth_auth_defaults_applied_response_t;


/* Authorization Opaque Data Structures (AODS) */

typedef struct {
    uint8_t id; /* SPDM_REGISTRY_ID_DMTF_DSP*/
    uint8_t vendor_id_len;
    uint16_t dmtf_spec_id;
    uint16_t opaque_element_data_len;
    /*
     * uint8_t aods_id;
     * uint8_t aods_body[];
     */
} spdm_auth_aods_table_header_t;

typedef struct {
    uint8_t aods_id;
} spdm_auth_aods_header_t;

/* AODS ID */
#define SPDM_AUTH_AODS_ID_INVOKE_SEAP 0
#define SPDM_AUTH_AODS_ID_SEAP_SUCCESS 1
#define SPDM_AUTH_AODS_ID_AUTH_HELLO 2

/* INVOKE_SEAP AODS */
typedef struct {
    uint8_t aods_id;
    uint8_t presence_extension;
    uint16_t credential_id;
} spdm_auth_aods_invoke_seap_t;

/* SEAP_SUCCESS AODS */
typedef struct {
    uint8_t aods_id;
    uint8_t presence_extension;
} spdm_auth_aods_seap_success_t;

/* AUTH_HELLO AODS */
typedef struct {
    uint8_t aods_id;
    uint8_t presence_extension;
} spdm_auth_aods_auth_hello_t;



/* Authorization record message definition */

/* Authorization Record Tag Format */
typedef struct {
    uint16_t credential_id;
    /* uint8_t Signature[Signature_len]; */
} spdm_auth_record_tag_t;

/* Authorization Record Type Message With Auth Format */
typedef struct {
    uint32_t auth_rec_id;
    uint32_t auth_tag_len;
    /*
     * spdm_auth_record_tag_t auth_tag;
     * uint32_t msg_to_auth_payload_len;
     * uint8_t msg_to_auth_payload[msg_to_auth_payload_len];
     * It should be spdm_auth_message_header_t or app message.
     */
} spdm_auth_record_type_msg_with_auth_t;

/* Authorization Record Type Record Error Format */
typedef struct {
    uint32_t error_auth_rec_id;
    spdm_auth_error_response_t auth_rec_error_info;
} spdm_auth_record_type_record_error_t;

/* Authorization Record Format */
typedef struct {
    uint8_t auth_record_type; /* SPDM_AUTH_RECORD_TYPE_* */
    uint8_t reserved;
    uint32_t payload_len;
    /*
     * uint8_t payload[payload_len];
     */
} spdm_auth_record_t;

/* Authorization Record Type */
#define SPDM_AUTH_RECORD_TYPE_AUTH_MESSAGE 0
#define SPDM_AUTH_RECORD_TYPE_MESSAGE_WITH_AUTH 1
#define SPDM_AUTH_RECORD_TYPE_RECORD_ERROR 2

/* Authorization vendor defined message*/

typedef struct {
    uint16_t standard_id; /* SPDM_REGISTRY_ID_DMTF_DSP */
    uint8_t len;
    uint16_t dmtf_spec_id;
    uint16_t payload_length;
} spdm_auth_vendor_defined_header_t;

typedef struct {
    spdm_message_header_t header;
    spdm_auth_vendor_defined_header_t auth_vendor_header;
    /*spdm_auth_record_t auth_record; */
} spdm_auth_vendor_defined_request_t;

/* SPDM VENDOR_DEFINED response */
typedef struct {
    spdm_message_header_t header;
    spdm_auth_vendor_defined_header_t auth_vendor_header;
    /*spdm_auth_record_t auth_record; */
} spdm_auth_vendor_defined_response_t;

#pragma pack()

#endif /* SPDM_AUTHORIZATION_H */
