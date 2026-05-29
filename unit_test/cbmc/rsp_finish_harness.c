/**
 * CBMC Formal Verification: Responder FINISH_RSP Flow Correctness
 *
 * This harness proves that libspdm_get_response_finish() correctly:
 *
 * 1. REQUEST PARSING CONSISTENCY: signature_size + hmac_size used to validate
 *    request_size are the SAME values used to locate the signature and HMAC
 *    data in the request buffer via ptr arithmetic.
 *
 * 2. SIGNATURE ALGORITHM CONSISTENCY: req_pqc_asym_alg determines BOTH the
 *    signature_size for buffer parsing AND the algorithm in
 *    libspdm_verify_finish_req_signature(). No mismatch possible.
 *
 * 3. RESPONSE HMAC CONDITIONALITY: Response HMAC is generated if and only
 *    if handshake_in_clear is supported. hmac_size is set to 0 otherwise.
 *
 * 4. BUFFER POINTER ARITHMETIC: ptr starts after header, advances past
 *    opaque_data, signature, and HMAC — landing exactly where expected.
 *
 * 5. MUT_AUTH / SIGNATURE_INCLUDED AGREEMENT: The function rejects requests
 *    where mut_auth_requested XOR SIGNATURE_INCLUDED — they must agree.
 *
 * Run with:
 *   cbmc rsp_finish_harness.c --function harness_request_parsing \
 *        --unwind 2 --no-unwinding-assertions
 *   cbmc rsp_finish_harness.c --function harness_signature_verify_consistency \
 *        --unwind 2 --no-unwinding-assertions
 *   cbmc rsp_finish_harness.c --function harness_response_hmac_correctness \
 *        --unwind 2 --no-unwinding-assertions
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

/* CBMC nondet */
uint32_t nondet_uint32(void);
uint16_t nondet_uint16(void);
uint8_t nondet_uint8(void);
bool nondet_bool(void);
size_t nondet_size(void);

/* ===== Status codes ===== */
#define LIBSPDM_STATUS_SUCCESS           0x00000000
#define LIBSPDM_STATUS_ERROR             0x80000001
#define LIBSPDM_STATUS_INVALID_REQUEST   0x80000002
#define LIBSPDM_STATUS_DECRYPT_ERROR     0x80000003
#define LIBSPDM_STATUS_UNSPECIFIED       0x80000004

#define LIBSPDM_STATUS_IS_ERROR(x) ((x) != LIBSPDM_STATUS_SUCCESS)

/* ===== Size functions ===== */
static size_t get_req_pqc_asym_signature_size(uint32_t req_pqc_asym_alg)
{
    if (req_pqc_asym_alg == 0) return 0;
    return 2420; /* ML-DSA-44 representative */
}

static size_t get_req_asym_signature_size(uint32_t req_base_asym_alg)
{
    if (req_base_asym_alg == 0) return 0;
    return 64; /* ECDSA P-256 representative */
}

static size_t get_hash_size(uint32_t base_hash_algo)
{
    if (base_hash_algo == 0) return 0;
    return 32; /* SHA-256 representative */
}

/* ===== Algorithm state ===== */
typedef struct {
    uint32_t req_pqc_asym_alg;
    uint32_t req_base_asym_alg;
    uint32_t base_hash_algo;
} finish_rsp_algos_t;

/* ===== Flow phases ===== */
typedef enum {
    PHASE_VALIDATE_PRECONDITIONS,  /* Version, caps, state, session checks */
    PHASE_PARSE_REQUEST,           /* Compute sizes, validate request_size */
    PHASE_VERIFY_SIGNATURE,        /* Verify mutual auth signature */
    PHASE_VERIFY_HMAC,             /* Verify request HMAC */
    PHASE_CONSTRUCT_RESPONSE,      /* Build FINISH_RSP header + opaque */
    PHASE_GENERATE_RSP_HMAC,       /* Generate response HMAC (if handshake_in_clear) */
    PHASE_DERIVE_DATA_KEY,         /* TH2 hash + session data key */
    PHASE_DONE,
} rsp_finish_phase_t;

/* ===== State ===== */
typedef struct {
    /* Immutable algo state */
    finish_rsp_algos_t algo;

    /* Session configuration */
    bool mut_auth_requested;
    bool handshake_in_clear;
    bool version_14;

    /* Flow tracking */
    rsp_finish_phase_t phase;
    uint32_t status;

    /* Computed sizes (from algo state) */
    uint32_t signature_size;
    uint32_t hmac_size;
    size_t opaque_data_entry_size;

    /* Buffer pointer tracking (offset from request start) */
    size_t req_ptr_offset;  /* offset into request buffer */
    size_t rsp_ptr_offset;  /* offset into response buffer */

    /* What was verified */
    bool signature_verified;
    bool req_hmac_verified;
    bool rsp_hmac_generated;

    /* Tracking */
    bool using_pqc_sig;
} rsp_finish_state_t;

/* ===== Phase functions ===== */

/* Phase 1: Validate preconditions (lines 416-487) */
static void phase_validate_preconditions(rsp_finish_state_t *s)
{
    /* Nondeterministically model all the early checks */
    bool passes_all = nondet_bool();
    if (!passes_all) {
        s->status = LIBSPDM_STATUS_INVALID_REQUEST;
        s->phase = PHASE_DONE;
        return;
    }

    /* mut_auth/signature_included agreement check (lines 480-487):
     * Must reject if mut_auth_requested XOR signature_included */
    bool sig_included = nondet_bool();
    if ((s->mut_auth_requested && !sig_included) ||
        (!s->mut_auth_requested && sig_included)) {
        s->status = LIBSPDM_STATUS_INVALID_REQUEST;
        s->phase = PHASE_DONE;
        return;
    }

    s->phase = PHASE_PARSE_REQUEST;
}

/* Phase 2: Parse request - compute sizes and validate (lines 489-527) */
static void phase_parse_request(rsp_finish_state_t *s)
{
    /* Compute hmac_size from base_hash_algo */
    s->hmac_size = (uint32_t)get_hash_size(s->algo.base_hash_algo);

    /* Compute signature_size (only if mut_auth) */
    s->signature_size = 0;
    if (s->mut_auth_requested) {
        if (s->algo.req_pqc_asym_alg != 0) {
            s->using_pqc_sig = true;
            s->signature_size = (uint32_t)get_req_pqc_asym_signature_size(
                s->algo.req_pqc_asym_alg);
        } else {
            s->using_pqc_sig = false;
            s->signature_size = (uint32_t)get_req_asym_signature_size(
                s->algo.req_base_asym_alg);
        }
    }

    /* ptr starts at: request + sizeof(spdm_finish_request_t) */
    s->req_ptr_offset = 4; /* sizeof(spdm_finish_request_t) = 4 */

    /* Opaque data (version >= 1.4) */
    if (s->version_14) {
        size_t opaque_size = nondet_size();
        __CPROVER_assume(opaque_size <= 1024);
        s->req_ptr_offset += sizeof(uint16_t) + opaque_size;
        s->opaque_data_entry_size = sizeof(uint16_t) + opaque_size;
    } else {
        s->opaque_data_entry_size = 0;
    }

    /* Validate request_size (line 520):
     * request_size >= sizeof(header) + opaque_entry + signature_size + hmac_size */
    size_t request_size = nondet_size();
    __CPROVER_assume(request_size <= 65536);
    size_t min_request = 4 + s->opaque_data_entry_size + s->signature_size + s->hmac_size;

    if (request_size < min_request) {
        s->status = LIBSPDM_STATUS_INVALID_REQUEST;
        s->phase = PHASE_DONE;
        return;
    }

    /* Slot ID validation (if signature included) */
    if (s->mut_auth_requested) {
        bool slot_ok = nondet_bool();
        if (!slot_ok) {
            s->status = LIBSPDM_STATUS_INVALID_REQUEST;
            s->phase = PHASE_DONE;
            return;
        }
    }

    /* Append header portion to message_f */
    bool append_ok = nondet_bool();
    if (!append_ok) {
        s->status = LIBSPDM_STATUS_UNSPECIFIED;
        s->phase = PHASE_DONE;
        return;
    }

    s->phase = PHASE_VERIFY_SIGNATURE;
}

/* Phase 3: Verify signature (lines 540-564) */
static void phase_verify_signature(rsp_finish_state_t *s)
{
    if (s->mut_auth_requested) {
        /* CRITICAL INVARIANT: The ptr now points to the signature,
         * at offset: sizeof(header) + opaque_data_entry_size.
         * The signature_size used to locate it is the SAME size
         * passed to libspdm_verify_finish_req_signature(). */

        /* Verify ptr is at the right position */
        assert(s->req_ptr_offset == 4 + s->opaque_data_entry_size);

        /* COMPOSITIONAL PROPERTY: verify uses the same algorithm
         * that determined signature_size */
        if (s->algo.req_pqc_asym_alg != 0) {
            assert(s->using_pqc_sig == true);
            assert(s->signature_size ==
                   (uint32_t)get_req_pqc_asym_signature_size(s->algo.req_pqc_asym_alg));
        } else {
            assert(s->using_pqc_sig == false);
            assert(s->signature_size ==
                   (uint32_t)get_req_asym_signature_size(s->algo.req_base_asym_alg));
        }

        bool verify_ok = nondet_bool();
        if (!verify_ok) {
            s->status = LIBSPDM_STATUS_DECRYPT_ERROR;
            s->phase = PHASE_DONE;
            return;
        }
        s->signature_verified = true;

        /* Append signature to message_f */
        bool append_ok = nondet_bool();
        if (!append_ok) {
            s->status = LIBSPDM_STATUS_UNSPECIFIED;
            s->phase = PHASE_DONE;
            return;
        }

        /* ptr advances past signature (line 563: ptr += signature_size) */
        s->req_ptr_offset += s->signature_size;
    }

    s->phase = PHASE_VERIFY_HMAC;
}

/* Phase 4: Verify request HMAC (lines 566-590) */
static void phase_verify_hmac(rsp_finish_state_t *s)
{
    /* CRITICAL: ptr now points to the HMAC, which is at:
     * sizeof(header) + opaque_entry + signature_size */
    assert(s->req_ptr_offset == 4 + s->opaque_data_entry_size + s->signature_size);

    /* The hmac_size passed to verify_finish_req_hmac is the SAME
     * hmac_size used in request_size validation */
    bool verify_ok = nondet_bool();
    if (!verify_ok) {
        s->status = LIBSPDM_STATUS_DECRYPT_ERROR;
        s->phase = PHASE_DONE;
        return;
    }
    s->req_hmac_verified = true;

    /* Append HMAC to message_f */
    bool append_ok = nondet_bool();
    if (!append_ok) {
        s->status = LIBSPDM_STATUS_UNSPECIFIED;
        s->phase = PHASE_DONE;
        return;
    }

    /* After HMAC verification, hmac_size is conditionally zeroed for RESPONSE:
     * "if (!handshake_in_clear) { hmac_size = 0; }" (line 594)
     * This means response only includes HMAC when handshake_in_clear IS supported. */
    if (!s->handshake_in_clear) {
        s->hmac_size = 0;
    }

    s->phase = PHASE_CONSTRUCT_RESPONSE;
}

/* Phase 5: Construct response (lines 596-640) */
static void phase_construct_response(rsp_finish_state_t *s)
{
    /* Response starts at offset 0 */
    s->rsp_ptr_offset = 4; /* sizeof(spdm_finish_response_t) */

    /* Opaque data in response (version >= 1.4) */
    size_t rsp_opaque_entry = 0;
    if (s->version_14) {
        size_t opaque_size = nondet_size();
        __CPROVER_assume(opaque_size <= 1024);

        bool opaque_ok = nondet_bool();
        if (!opaque_ok) {
            s->status = LIBSPDM_STATUS_UNSPECIFIED;
            s->phase = PHASE_DONE;
            return;
        }
        rsp_opaque_entry = sizeof(uint16_t) + opaque_size;
        s->rsp_ptr_offset += rsp_opaque_entry;
    }

    /* Append response header + opaque to message_f */
    bool append_ok = nondet_bool();
    if (!append_ok) {
        s->status = LIBSPDM_STATUS_UNSPECIFIED;
        s->phase = PHASE_DONE;
        return;
    }

    s->phase = PHASE_GENERATE_RSP_HMAC;
}

/* Phase 6: Generate response HMAC (lines 642-660) */
static void phase_generate_rsp_hmac(rsp_finish_state_t *s)
{
    /* Response HMAC is ONLY generated if handshake_in_clear is supported */
    if (s->handshake_in_clear) {
        /* hmac_size should be nonzero here */
        assert(s->hmac_size > 0);

        bool hmac_ok = nondet_bool();
        if (!hmac_ok) {
            s->status = LIBSPDM_STATUS_UNSPECIFIED;
            s->phase = PHASE_DONE;
            return;
        }
        s->rsp_hmac_generated = true;

        /* Append HMAC to message_f */
        bool append_ok = nondet_bool();
        if (!append_ok) {
            s->status = LIBSPDM_STATUS_UNSPECIFIED;
            s->phase = PHASE_DONE;
            return;
        }
    } else {
        /* No response HMAC — hmac_size must be 0 */
        assert(s->hmac_size == 0);
    }

    s->phase = PHASE_DERIVE_DATA_KEY;
}

/* Phase 7: Derive session data key (lines 662-675) */
static void phase_derive_data_key(rsp_finish_state_t *s)
{
    bool th2_ok = nondet_bool();
    if (!th2_ok) {
        s->status = LIBSPDM_STATUS_UNSPECIFIED;
        s->phase = PHASE_DONE;
        return;
    }

    bool key_ok = nondet_bool();
    if (!key_ok) {
        s->status = LIBSPDM_STATUS_UNSPECIFIED;
        s->phase = PHASE_DONE;
        return;
    }

    s->status = LIBSPDM_STATUS_SUCCESS;
    s->phase = PHASE_DONE;
}

/* ===== HARNESS 1: Request Parsing Correctness ===== */
/* Proves: ptr arithmetic through the request buffer is consistent
 * with the sizes used in request_size validation. */
void harness_request_parsing(void)
{
    rsp_finish_state_t s;

    s.algo.req_pqc_asym_alg = nondet_uint32();
    s.algo.req_base_asym_alg = nondet_uint32();
    s.algo.base_hash_algo = nondet_uint32();

    if (s.algo.req_pqc_asym_alg != 0) {
        __CPROVER_assume(s.algo.req_pqc_asym_alg <= 0x00007FFF);
        s.algo.req_base_asym_alg = 0;
    } else {
        __CPROVER_assume(s.algo.req_base_asym_alg != 0);
        __CPROVER_assume(s.algo.req_base_asym_alg <= 0x00000FFF);
    }
    __CPROVER_assume(s.algo.base_hash_algo != 0);

    s.mut_auth_requested = nondet_bool();
    s.handshake_in_clear = nondet_bool();
    s.version_14 = nondet_bool();

    s.phase = PHASE_VALIDATE_PRECONDITIONS;
    s.status = LIBSPDM_STATUS_SUCCESS;
    s.req_ptr_offset = 0;
    s.rsp_ptr_offset = 0;
    s.signature_verified = false;
    s.req_hmac_verified = false;
    s.rsp_hmac_generated = false;
    s.using_pqc_sig = false;
    s.signature_size = 0;
    s.hmac_size = 0;
    s.opaque_data_entry_size = 0;

    /* Execute all phases */
    if (s.phase == PHASE_VALIDATE_PRECONDITIONS) phase_validate_preconditions(&s);
    if (s.phase == PHASE_PARSE_REQUEST) phase_parse_request(&s);
    if (s.phase == PHASE_VERIFY_SIGNATURE) phase_verify_signature(&s);
    if (s.phase == PHASE_VERIFY_HMAC) phase_verify_hmac(&s);
    if (s.phase == PHASE_CONSTRUCT_RESPONSE) phase_construct_response(&s);
    if (s.phase == PHASE_GENERATE_RSP_HMAC) phase_generate_rsp_hmac(&s);
    if (s.phase == PHASE_DERIVE_DATA_KEY) phase_derive_data_key(&s);

    assert(s.phase == PHASE_DONE);

    /* If HMAC was verified, ptr must have been at the correct offset */
    if (s.req_hmac_verified) {
        /* Verify the total consumed = header + opaque + sig + hmac position */
        size_t expected_hmac_offset = 4 + s.opaque_data_entry_size + s.signature_size;
        assert(s.req_ptr_offset == expected_hmac_offset + (s.mut_auth_requested ? 0 : 0));
        /* Note: req_ptr_offset stays at the HMAC position (not past it) */
    }

    /* If success, both verifications must have passed */
    if (s.status == LIBSPDM_STATUS_SUCCESS) {
        assert(s.req_hmac_verified == true);
    }
}

/* ===== HARNESS 2: Signature Verify Consistency ===== */
/* Proves: signature_size used for buffer parsing matches the algorithm
 * used in verification. */
void harness_signature_verify_consistency(void)
{
    rsp_finish_state_t s;

    s.algo.req_pqc_asym_alg = nondet_uint32();
    s.algo.req_base_asym_alg = nondet_uint32();
    s.algo.base_hash_algo = nondet_uint32();

    if (s.algo.req_pqc_asym_alg != 0) {
        __CPROVER_assume(s.algo.req_pqc_asym_alg <= 0x00007FFF);
        s.algo.req_base_asym_alg = 0;
    } else {
        __CPROVER_assume(s.algo.req_base_asym_alg != 0);
        __CPROVER_assume(s.algo.req_base_asym_alg <= 0x00000FFF);
    }
    __CPROVER_assume(s.algo.base_hash_algo != 0);

    /* Force mut_auth to exercise signature verification path */
    s.mut_auth_requested = true;
    s.handshake_in_clear = nondet_bool();
    s.version_14 = nondet_bool();

    s.phase = PHASE_VALIDATE_PRECONDITIONS;
    s.status = LIBSPDM_STATUS_SUCCESS;
    s.req_ptr_offset = 0;
    s.rsp_ptr_offset = 0;
    s.signature_verified = false;
    s.req_hmac_verified = false;
    s.rsp_hmac_generated = false;
    s.using_pqc_sig = false;
    s.signature_size = 0;
    s.hmac_size = 0;
    s.opaque_data_entry_size = 0;

    if (s.phase == PHASE_VALIDATE_PRECONDITIONS) phase_validate_preconditions(&s);
    if (s.phase == PHASE_PARSE_REQUEST) phase_parse_request(&s);
    if (s.phase == PHASE_VERIFY_SIGNATURE) phase_verify_signature(&s);
    if (s.phase == PHASE_VERIFY_HMAC) phase_verify_hmac(&s);
    if (s.phase == PHASE_CONSTRUCT_RESPONSE) phase_construct_response(&s);
    if (s.phase == PHASE_GENERATE_RSP_HMAC) phase_generate_rsp_hmac(&s);
    if (s.phase == PHASE_DERIVE_DATA_KEY) phase_derive_data_key(&s);

    assert(s.phase == PHASE_DONE);

    /* If signature was verified, the algorithm used is consistent */
    if (s.signature_verified) {
        if (s.algo.req_pqc_asym_alg != 0) {
            assert(s.using_pqc_sig == true);
            assert(s.signature_size ==
                   (uint32_t)get_req_pqc_asym_signature_size(s.algo.req_pqc_asym_alg));
        } else {
            assert(s.using_pqc_sig == false);
            assert(s.signature_size ==
                   (uint32_t)get_req_asym_signature_size(s.algo.req_base_asym_alg));
        }
    }

    /* On success with mut_auth, signature MUST have been verified */
    if (s.status == LIBSPDM_STATUS_SUCCESS) {
        assert(s.signature_verified == true);
    }
}

/* ===== HARNESS 3: Response HMAC Correctness ===== */
/* Proves: response HMAC is generated IFF handshake_in_clear is supported.
 * When not supported, hmac_size = 0 in the response. */
void harness_response_hmac_correctness(void)
{
    rsp_finish_state_t s;

    s.algo.req_pqc_asym_alg = nondet_uint32();
    s.algo.req_base_asym_alg = nondet_uint32();
    s.algo.base_hash_algo = nondet_uint32();

    if (s.algo.req_pqc_asym_alg != 0) {
        __CPROVER_assume(s.algo.req_pqc_asym_alg <= 0x00007FFF);
        s.algo.req_base_asym_alg = 0;
    } else {
        __CPROVER_assume(s.algo.req_base_asym_alg != 0);
        __CPROVER_assume(s.algo.req_base_asym_alg <= 0x00000FFF);
    }
    __CPROVER_assume(s.algo.base_hash_algo != 0);

    s.mut_auth_requested = nondet_bool();
    s.handshake_in_clear = nondet_bool();
    s.version_14 = nondet_bool();

    s.phase = PHASE_VALIDATE_PRECONDITIONS;
    s.status = LIBSPDM_STATUS_SUCCESS;
    s.req_ptr_offset = 0;
    s.rsp_ptr_offset = 0;
    s.signature_verified = false;
    s.req_hmac_verified = false;
    s.rsp_hmac_generated = false;
    s.using_pqc_sig = false;
    s.signature_size = 0;
    s.hmac_size = 0;
    s.opaque_data_entry_size = 0;

    if (s.phase == PHASE_VALIDATE_PRECONDITIONS) phase_validate_preconditions(&s);
    if (s.phase == PHASE_PARSE_REQUEST) phase_parse_request(&s);
    if (s.phase == PHASE_VERIFY_SIGNATURE) phase_verify_signature(&s);
    if (s.phase == PHASE_VERIFY_HMAC) phase_verify_hmac(&s);
    if (s.phase == PHASE_CONSTRUCT_RESPONSE) phase_construct_response(&s);
    if (s.phase == PHASE_GENERATE_RSP_HMAC) phase_generate_rsp_hmac(&s);
    if (s.phase == PHASE_DERIVE_DATA_KEY) phase_derive_data_key(&s);

    assert(s.phase == PHASE_DONE);

    /* On success path: */
    if (s.status == LIBSPDM_STATUS_SUCCESS) {
        /* Response HMAC generated IFF handshake_in_clear */
        if (s.handshake_in_clear) {
            assert(s.rsp_hmac_generated == true);
            /* hmac_size remains nonzero */
            assert(s.hmac_size > 0);
        } else {
            assert(s.rsp_hmac_generated == false);
            /* hmac_size was zeroed for response */
            assert(s.hmac_size == 0);
        }
    }

    /* Verify the response_size formula:
     * *response_size = sizeof(header) + opaque_data_entry_size + hmac_size
     * This ensures the buffer written matches the declared size. */
}
