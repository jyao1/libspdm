/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_crypt_lib.h"
#include "hal/library/cryptlib.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"

bool libspdm_asym_func_need_hash(uint32_t base_asym_algo);

bool libspdm_asym_verify_wrap(
    void *context, size_t hash_nid, uint32_t base_asym_algo,
    const uint8_t *param, size_t param_size,
    const uint8_t *message, size_t message_size,
    const uint8_t *signature, size_t sig_size);

bool libspdm_asym_sign_wrap (
    void *context, size_t hash_nid, uint32_t base_asym_algo,
    const uint8_t *param, size_t param_size,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size);
