/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_SETCERTLIB_H
#define RESPONDER_SETCERTLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * return if current code is running in a trusted environment.
 *
 * @param[in]  spdm_context  A pointer to the SPDM context.
 *
 * @retval  true   It is in a trusted environment.
 * @retval  false  It is not in a trusted environment.
 **/
extern bool libspdm_is_in_trusted_environment(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context
#endif
    );

/**
 * Stores or erase a certificate chain in non-volatile memory.
 * If the cert_chain is NULL and cert_chain_size is 0,
 * the feature is to erase the certificate chain.
 *
 * @param[in]  spdm_context     A pointer to the SPDM context.
 * @param[in]  slot_id          The number of slot for the certificate chain.
 * @param[in]  cert_chain       The pointer for the certificate chain to set.
 * @param[in]  cert_chain_size  The size of the certificate chain to set.
 * @param[in]  base_hash_algo   Indicates the negotiated hash algorithm.
 * @param[in]  base_asym_algo   Indicates the negotiated signing algorithms.
 * @param[in,out] need_reset    On input, indicates the value of CERT_INSTALL_RESET_CAP.
 *                              On output, indicates whether the device needs to be reset (true) for
 *                              the SET_CERTIFICATE operation to complete.
 * @param[out]  is_busy         If true, indicates that the certificate chain cannot be written at
 *                              this time, but it may be successful in a later call. The function's
 *                              return value must be false if this parameter is true.
 * @retval true   The certificate chain was successfully written to non-volatile memory.
 * @retval false  Unable to write certificate chain to non-volatile memory.
 **/
extern bool libspdm_write_certificate_to_nvm(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint8_t slot_id, const void * cert_chain,
    size_t cert_chain_size,
    uint32_t base_hash_algo, uint32_t base_asym_algo
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *need_reset, bool *is_busy
#endif /* LIBSPDM_SET_CERT_CSR_PARAMS */
    );

extern bool libspdm_write_pqc_certificate_to_nvm(
    void *spdm_context,
    uint8_t slot_id, const void * cert_chain,
    size_t cert_chain_size,
    uint32_t base_hash_algo, uint32_t pqc_asym_algo,
    bool *need_reset, bool *is_busy
    );

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#endif /* RESPONDER_SETCERTLIB_H */
