/**
 * CBMC Formal Verification Harness
 *
 * Verifies patch e96fe9ff7583361014f5a9d6a1c272dff57a3d5f:
 * "Add SPDM_CAPABILITIES chunk with Supported Algorithms"
 *
 * Property to prove:
 *   After the chunked-response validation logic, if status == SUCCESS and the
 *   response code is SPDM_CAPABILITIES, then param1 must have
 *   SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS (bit 0) set.
 *
 *   Equivalently: a chunked CAPABILITIES response WITHOUT Supported Algorithms
 *   is ALWAYS rejected with LIBSPDM_STATUS_INVALID_MSG_FIELD.
 *
 * This models ONLY the decision logic introduced by the patch (lines 805-822),
 * abstracting away all surrounding context (transport, crypto, buffers).
 *
 * Run with:
 *   cbmc patch_e96fe9f_harness.c --function harness \
 *        --unwind 1 --no-unwinding-assertions
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

/* ===== Minimal definitions mirroring libspdm ===== */

#define SPDM_VERSION       0x04
#define SPDM_CAPABILITIES  0x61
#define SPDM_ERROR         0x7F

#define SPDM_ERROR_CODE_LARGE_RESPONSE 0x0D

#define SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS 0x01

/* Simplified return type */
typedef uint32_t libspdm_return_t;
#define LIBSPDM_STATUS_SUCCESS          0x00000000
#define LIBSPDM_STATUS_INVALID_MSG_FIELD 0x80010003
#define LIBSPDM_STATUS_INVALID_MSG_SIZE  0x80010002

#define LIBSPDM_STATUS_IS_ERROR(x) (((x) & 0x80000000) != 0)

/* Minimal SPDM message header */
typedef struct {
    uint8_t spdm_version;
    uint8_t request_response_code;
    uint8_t param1;
    uint8_t param2;
} spdm_message_header_t;

/* CBMC nondet functions */
uint8_t nondet_uint8(void);
uint32_t nondet_uint32(void);
bool nondet_bool(void);
size_t nondet_size(void);

/* ===== Model of libspdm_handle_error_large_response =====
 * This function is called when the initial response is ERROR(LARGE_RESPONSE).
 * It performs CHUNK_GET to retrieve the actual large response.
 * We model it as nondeterministically succeeding and populating the
 * response header with arbitrary values (simulating any possible chunked response).
 */
libspdm_return_t model_handle_error_large_response(
    spdm_message_header_t *spdm_response,
    size_t *response_size)
{
    libspdm_return_t status = nondet_uint32();

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    /* On success, the response buffer is filled with the reassembled message */
    spdm_response->spdm_version = nondet_uint8();
    spdm_response->request_response_code = nondet_uint8();
    spdm_response->param1 = nondet_uint8();
    spdm_response->param2 = nondet_uint8();

    /* The response size is at least a header */
    size_t new_size = nondet_size();
    __CPROVER_assume(new_size >= sizeof(spdm_message_header_t));
    *response_size = new_size;

    return LIBSPDM_STATUS_SUCCESS;
}

/* ===== The harness models the patched validation logic ===== */
void harness(void)
{
    spdm_message_header_t response_buf;
    spdm_message_header_t *spdm_response = &response_buf;
    size_t response_size;
    libspdm_return_t status;

    /* --- Simulate: initial response is ERROR(LARGE_RESPONSE) --- */
    /* The code enters the large-response path */

    /* Model: libspdm_handle_error_large_response returns */
    status = model_handle_error_large_response(spdm_response, &response_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    if (response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    /* === PATCHED CODE (lines 805-822) === */

    /* Per the spec, SPDM_VERSION shall not be chunked */
    if (spdm_response->request_response_code == SPDM_VERSION) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    /* Per the spec, SPDM_CAPABILITIES shall not be chunked unless
     * the response includes Supported Algorithms. */
    if (spdm_response->request_response_code == SPDM_CAPABILITIES) {
        if ((spdm_response->param1 &
             SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS) == 0) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }

    /* If we reach here, status is SUCCESS */
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    /* ===== PROPERTIES TO VERIFY ===== */

    /* Property 1: If status is SUCCESS and response code is CAPABILITIES,
     * then Supported Algorithms bit MUST be set. */
    if (!LIBSPDM_STATUS_IS_ERROR(status) &&
        spdm_response->request_response_code == SPDM_CAPABILITIES) {
        assert((spdm_response->param1 &
                SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS) != 0);
    }

    /* Property 2: If status is SUCCESS and response code is VERSION,
     * that is impossible (VERSION is always rejected). */
    if (!LIBSPDM_STATUS_IS_ERROR(status)) {
        assert(spdm_response->request_response_code != SPDM_VERSION);
    }

    /* Property 3: A chunked CAPABILITIES without Supported Algorithms
     * is always rejected (status is error). */
    if (spdm_response->request_response_code == SPDM_CAPABILITIES &&
        (spdm_response->param1 &
         SPDM_CAPABILITIES_RESPONSE_PARAM1_SUPPORTED_ALGORITHMS) == 0) {
        assert(LIBSPDM_STATUS_IS_ERROR(status));
    }
}
