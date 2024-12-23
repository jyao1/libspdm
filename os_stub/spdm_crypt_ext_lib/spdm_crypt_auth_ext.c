/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_lib_config.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"
#include "hal/library/cryptlib.h"
#include "library/spdm_crypt_lib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"

bool libspdm_auth_asym_get_private_key_from_pem(uint64_t auth_base_algo,
                                                const uint8_t *pem_data,
                                                size_t pem_size,
                                                const char *password,
                                                void **context)
{
    uint32_t base_asym_algo;
    base_asym_algo = libspdm_auth_base_algo_to_spdm_base_asym_algo(auth_base_algo);
    return libspdm_asym_get_private_key_from_pem(
        base_asym_algo, pem_data, pem_size, password, context);
}
