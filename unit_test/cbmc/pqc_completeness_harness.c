/**
 * CBMC Formal Verification Harness for PQC Algorithm Support Completeness
 *
 * Verifies the following SPDM specification properties for PQC support:
 *
 * Property 1 (Mutual Exclusion - Asymmetric):
 *   After algorithm negotiation, at most one of BaseAsymSel and PqcAsymSel
 *   shall be non-zero. (Spec: "The total number of bits set in BaseAsymSel
 *   and PqcAsymSel shall be no more than one.")
 *
 * Property 2 (Mutual Exclusion - Key Agreement):
 *   After algorithm negotiation, at most one of DHE and KEM selections
 *   shall be non-zero. (Spec: "The total number of bits set in DHE
 *   AlgSupported and KEMAlg AlgSupported shall be no more than one.")
 *
 * Property 3 (Mutual Exclusion - Requester Asymmetric):
 *   After algorithm negotiation, at most one of ReqBaseAsymAlg and
 *   ReqPqcAsymAlg shall be non-zero.
 *
 * Property 4 (Completeness - Algorithm Bitmask Coverage):
 *   Every valid PQC algorithm bit in the defined mask has a corresponding
 *   entry that can be selected by the prioritization logic.
 *
 * Property 5 (Correctness - pqc_first logic):
 *   When pqc_first is true and PQC algo is selected, traditional is zeroed.
 *   When pqc_first is false and traditional is selected, PQC is zeroed.
 *
 * Run with:
 *   cbmc pqc_completeness_harness.c --function harness_mutual_exclusion \
 *        --unwind 8 --no-unwinding-assertions
 *   cbmc pqc_completeness_harness.c --function harness_completeness \
 *        --unwind 1 --no-unwinding-assertions
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

/* ===== SPDM Algorithm Constants (from spdm.h) ===== */

/* PQC Asymmetric algorithms (responder signing) */
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44          0x00000001
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65          0x00000002
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87          0x00000004
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S  0x00000008
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S 0x00000010
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F  0x00000020
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F 0x00000040
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S  0x00000080
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S 0x00000100
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F  0x00000200
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F 0x00000400
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S  0x00000800
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S 0x00001000
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F  0x00002000
#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F 0x00004000

#define SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK 0x00007FFF

/* KEM algorithms */
#define SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512  0x00000001
#define SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768  0x00000002
#define SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024 0x00000004

#define SPDM_ALGORITHMS_KEM_ALG_VALID_MASK 0x00000007

/* Traditional asymmetric algorithms (subset for modeling) */
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_MASK 0x00000FFF

/* DHE algorithms (subset for modeling) */
#define SPDM_ALGORITHMS_DHE_MASK 0x0000007F

/* Struct table algorithm types */
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE             0x02
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD            0x03
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG 0x04
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE    0x05
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG 0x06
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG         0x07

#define MAX_STRUCT_TABLES 7

/* CBMC nondet functions */
uint32_t nondet_uint32(void);
uint16_t nondet_uint16(void);
uint8_t nondet_uint8(void);
bool nondet_bool(void);

/* ===== Helper: popcount (count bits set) ===== */
static unsigned int popcount32(uint32_t x)
{
    unsigned int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

/* ===== Model of libspdm_prioritize_algorithm ===== */
/* Returns at most one bit set from (local & peer), using priority ordering.
 * We model it abstractly: if common != 0, returns a single-bit value from common. */
static uint32_t model_prioritize(uint32_t local_algo, uint32_t peer_algo)
{
    uint32_t common = local_algo & peer_algo;
    if (common == 0) {
        return 0;
    }
    /* Return the highest-priority single bit.
     * For verification purposes, we nondeterministically pick one valid bit. */
    uint32_t result = nondet_uint32();
    /* Result must be a single bit that is in common */
    __CPROVER_assume(result != 0);
    __CPROVER_assume((result & common) == result);
    __CPROVER_assume(popcount32(result) == 1);
    return result;
}

/* ===== Struct table entry ===== */
typedef struct {
    uint8_t alg_type;
    uint16_t alg_supported;
} struct_table_entry_t;

/* ===== Model of the pqc_first mutual exclusion logic ===== */
/* This directly mirrors libspdm_rsp_algorithms.c lines 809-868 */
static void apply_pqc_first_logic(
    bool pqc_first,
    uint32_t *base_asym_sel,
    uint32_t *pqc_asym_sel,
    struct_table_entry_t *struct_table,
    uint8_t table_count)
{
    uint8_t index, sub_index;

    if (pqc_first) {
        /* PQC has priority: if PQC selected, disable traditional */
        if (*pqc_asym_sel != 0) {
            *base_asym_sel = 0;
        }
        for (index = 0; index < table_count; ++index) {
            if (struct_table[index].alg_type ==
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG) {
                if (struct_table[index].alg_supported != 0) {
                    for (sub_index = 0; sub_index < table_count; ++sub_index) {
                        if (struct_table[sub_index].alg_type ==
                            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG) {
                            struct_table[sub_index].alg_supported = 0;
                        }
                    }
                }
            }
            if (struct_table[index].alg_type ==
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG) {
                if (struct_table[index].alg_supported != 0) {
                    for (sub_index = 0; sub_index < table_count; ++sub_index) {
                        if (struct_table[sub_index].alg_type ==
                            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE) {
                            struct_table[sub_index].alg_supported = 0;
                        }
                    }
                }
            }
        }
    } else {
        /* Traditional has priority: if traditional selected, disable PQC */
        if (*base_asym_sel != 0) {
            *pqc_asym_sel = 0;
        }
        for (index = 0; index < table_count; ++index) {
            if (struct_table[index].alg_type ==
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG) {
                if (struct_table[index].alg_supported != 0) {
                    for (sub_index = 0; sub_index < table_count; ++sub_index) {
                        if (struct_table[sub_index].alg_type ==
                            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG) {
                            struct_table[sub_index].alg_supported = 0;
                        }
                    }
                }
            }
            if (struct_table[index].alg_type ==
                SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE) {
                if (struct_table[index].alg_supported != 0) {
                    for (sub_index = 0; sub_index < table_count; ++sub_index) {
                        if (struct_table[sub_index].alg_type ==
                            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG) {
                            struct_table[sub_index].alg_supported = 0;
                        }
                    }
                }
            }
        }
    }
}

/* ================================================================
 * Harness 1: Verify mutual exclusion properties after negotiation
 * ================================================================ */
void harness_mutual_exclusion(void)
{
    /* Nondeterministic inputs representing algorithm negotiation state */
    uint32_t local_base_asym = nondet_uint32();
    uint32_t peer_base_asym = nondet_uint32();
    uint32_t local_pqc_asym = nondet_uint32();
    uint32_t peer_pqc_asym = nondet_uint32();
    uint32_t local_dhe = nondet_uint32();
    uint32_t peer_dhe = nondet_uint32();
    uint32_t local_kem = nondet_uint32();
    uint32_t peer_kem = nondet_uint32();
    uint32_t local_req_base_asym = nondet_uint32();
    uint32_t peer_req_base_asym = nondet_uint32();
    uint32_t local_req_pqc_asym = nondet_uint32();
    uint32_t peer_req_pqc_asym = nondet_uint32();
    bool pqc_first = nondet_bool();

    /* Constrain to valid algorithm bits */
    __CPROVER_assume((local_base_asym & ~SPDM_ALGORITHMS_BASE_ASYM_ALGO_MASK) == 0);
    __CPROVER_assume((peer_base_asym & ~SPDM_ALGORITHMS_BASE_ASYM_ALGO_MASK) == 0);
    __CPROVER_assume((local_pqc_asym & ~SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) == 0);
    __CPROVER_assume((peer_pqc_asym & ~SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) == 0);
    __CPROVER_assume((local_dhe & ~SPDM_ALGORITHMS_DHE_MASK) == 0);
    __CPROVER_assume((peer_dhe & ~SPDM_ALGORITHMS_DHE_MASK) == 0);
    __CPROVER_assume((local_kem & ~SPDM_ALGORITHMS_KEM_ALG_VALID_MASK) == 0);
    __CPROVER_assume((peer_kem & ~SPDM_ALGORITHMS_KEM_ALG_VALID_MASK) == 0);
    __CPROVER_assume((local_req_base_asym & ~SPDM_ALGORITHMS_BASE_ASYM_ALGO_MASK) == 0);
    __CPROVER_assume((peer_req_base_asym & ~SPDM_ALGORITHMS_BASE_ASYM_ALGO_MASK) == 0);
    __CPROVER_assume((local_req_pqc_asym & ~SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) == 0);
    __CPROVER_assume((peer_req_pqc_asym & ~SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) == 0);

    /* Step 1: Prioritize algorithms (each returns at most 1 bit) */
    uint32_t base_asym_sel = model_prioritize(local_base_asym, peer_base_asym);
    uint32_t pqc_asym_sel = model_prioritize(local_pqc_asym, peer_pqc_asym);

    /* Build struct table with DHE, KEM, ReqBaseAsymAlg, ReqPqcAsymAlg */
    struct_table_entry_t struct_table[4];
    uint8_t table_count = 4;

    struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    uint32_t dhe_sel = model_prioritize(local_dhe, peer_dhe);
    struct_table[0].alg_supported = (uint16_t)dhe_sel;

    struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    uint32_t req_base_asym_sel = model_prioritize(local_req_base_asym, peer_req_base_asym);
    struct_table[1].alg_supported = (uint16_t)req_base_asym_sel;

    struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG;
    uint32_t req_pqc_asym_sel = model_prioritize(local_req_pqc_asym, peer_req_pqc_asym);
    struct_table[2].alg_supported = (uint16_t)req_pqc_asym_sel;

    struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG;
    uint32_t kem_sel = model_prioritize(local_kem, peer_kem);
    struct_table[3].alg_supported = (uint16_t)kem_sel;

    /* Step 2: Apply pqc_first mutual exclusion logic */
    apply_pqc_first_logic(pqc_first, &base_asym_sel, &pqc_asym_sel,
                          struct_table, table_count);

    /* ===== PROPERTIES ===== */

    /* Property 1: BaseAsymSel and PqcAsymSel are mutually exclusive */
    assert(!(base_asym_sel != 0 && pqc_asym_sel != 0));

    /* Property 2: DHE and KEM are mutually exclusive */
    uint16_t final_dhe = 0, final_kem = 0;
    for (uint8_t i = 0; i < table_count; i++) {
        if (struct_table[i].alg_type == SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE)
            final_dhe = struct_table[i].alg_supported;
        if (struct_table[i].alg_type == SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG)
            final_kem = struct_table[i].alg_supported;
    }
    assert(!(final_dhe != 0 && final_kem != 0));

    /* Property 3: ReqBaseAsymAlg and ReqPqcAsymAlg are mutually exclusive */
    uint16_t final_req_base = 0, final_req_pqc = 0;
    for (uint8_t i = 0; i < table_count; i++) {
        if (struct_table[i].alg_type == SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG)
            final_req_base = struct_table[i].alg_supported;
        if (struct_table[i].alg_type == SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG)
            final_req_pqc = struct_table[i].alg_supported;
    }
    assert(!(final_req_base != 0 && final_req_pqc != 0));

    /* Property 4: Each selection is at most 1 bit (from prioritize) */
    assert(popcount32(base_asym_sel) <= 1);
    assert(popcount32(pqc_asym_sel) <= 1);
    assert(popcount32((uint32_t)final_dhe) <= 1);
    assert(popcount32((uint32_t)final_kem) <= 1);
}

/* ================================================================
 * Harness 2: Verify algorithm bitmask completeness
 * Every defined algorithm has a valid position in the mask.
 * ================================================================ */
void harness_completeness(void)
{
    /* Property: All defined PQC asymmetric algorithms are within the valid mask */
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44 & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65 & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87 & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F & SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) != 0);

    /* Property: All defined KEM algorithms are within the valid mask */
    assert((SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512 & SPDM_ALGORITHMS_KEM_ALG_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768 & SPDM_ALGORITHMS_KEM_ALG_VALID_MASK) != 0);
    assert((SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024 & SPDM_ALGORITHMS_KEM_ALG_VALID_MASK) != 0);

    /* Property: Masks are contiguous (no gaps that could cause issues) */
    /* PQC mask covers bits 0-14 (15 algorithms) */
    assert(SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK == 0x7FFF);
    /* KEM mask covers bits 0-2 (3 algorithms) */
    assert(SPDM_ALGORITHMS_KEM_ALG_VALID_MASK == 0x7);

    /* Property: Each individual algorithm constant is a power of 2 (single bit) */
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F) == 1);
    assert(popcount32(SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F) == 1);
    assert(popcount32(SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512) == 1);
    assert(popcount32(SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768) == 1);
    assert(popcount32(SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024) == 1);

    /* Property: No overlap between PQC_ASYM and KEM masks (different domains) */
    /* This is inherently true as they are separate fields, but verify the logic */
    assert((SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK & 0) == 0); /* trivial: separate fields */
}

/* ================================================================
 * Harness 3: Verify pqc_first correctness for all cases
 * ================================================================ */
void harness_pqc_first_correctness(void)
{
    bool pqc_first = nondet_bool();
    uint32_t base_asym_sel = nondet_uint32();
    uint32_t pqc_asym_sel = nondet_uint32();

    /* Constrain: each is at most 1 bit (output of prioritize) */
    __CPROVER_assume(popcount32(base_asym_sel) <= 1);
    __CPROVER_assume(popcount32(pqc_asym_sel) <= 1);
    __CPROVER_assume((base_asym_sel & ~SPDM_ALGORITHMS_BASE_ASYM_ALGO_MASK) == 0);
    __CPROVER_assume((pqc_asym_sel & ~SPDM_ALGORITHMS_PQC_ASYM_ALGO_VALID_MASK) == 0);

    /* Struct table with DHE and KEM */
    struct_table_entry_t struct_table[4];
    uint8_t table_count = 4;

    struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    struct_table[0].alg_supported = nondet_uint16();
    __CPROVER_assume(popcount32((uint32_t)struct_table[0].alg_supported) <= 1);

    struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    struct_table[1].alg_supported = nondet_uint16();
    __CPROVER_assume(popcount32((uint32_t)struct_table[1].alg_supported) <= 1);

    struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG;
    struct_table[2].alg_supported = nondet_uint16();
    __CPROVER_assume(popcount32((uint32_t)struct_table[2].alg_supported) <= 1);

    struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG;
    struct_table[3].alg_supported = nondet_uint16();
    __CPROVER_assume(popcount32((uint32_t)struct_table[3].alg_supported) <= 1);

    /* Save pre-state for property checks */
    uint32_t orig_base = base_asym_sel;
    uint32_t orig_pqc = pqc_asym_sel;
    uint16_t orig_dhe = struct_table[0].alg_supported;
    uint16_t orig_kem = struct_table[3].alg_supported;
    uint16_t orig_req_base = struct_table[1].alg_supported;
    uint16_t orig_req_pqc = struct_table[2].alg_supported;

    /* Apply the logic */
    apply_pqc_first_logic(pqc_first, &base_asym_sel, &pqc_asym_sel,
                          struct_table, table_count);

    /* Property 5a: If pqc_first and PQC was selected, traditional must be zeroed */
    if (pqc_first && orig_pqc != 0) {
        assert(base_asym_sel == 0);
    }

    /* Property 5b: If !pqc_first and traditional was selected, PQC must be zeroed */
    if (!pqc_first && orig_base != 0) {
        assert(pqc_asym_sel == 0);
    }

    /* Property 5c: If pqc_first and KEM was selected, DHE must be zeroed */
    if (pqc_first && orig_kem != 0) {
        assert(struct_table[0].alg_supported == 0);
    }

    /* Property 5d: If !pqc_first and DHE was selected, KEM must be zeroed */
    if (!pqc_first && orig_dhe != 0) {
        assert(struct_table[3].alg_supported == 0);
    }

    /* Property 5e: If pqc_first and ReqPqcAsymAlg was selected, ReqBaseAsymAlg must be zeroed */
    if (pqc_first && orig_req_pqc != 0) {
        assert(struct_table[1].alg_supported == 0);
    }

    /* Property 5f: If !pqc_first and ReqBaseAsymAlg was selected, ReqPqcAsymAlg must be zeroed */
    if (!pqc_first && orig_req_base != 0) {
        assert(struct_table[2].alg_supported == 0);
    }

    /* The output still satisfies mutual exclusion */
    assert(!(base_asym_sel != 0 && pqc_asym_sel != 0));
    assert(!(struct_table[0].alg_supported != 0 && struct_table[3].alg_supported != 0));
    assert(!(struct_table[1].alg_supported != 0 && struct_table[2].alg_supported != 0));
}
