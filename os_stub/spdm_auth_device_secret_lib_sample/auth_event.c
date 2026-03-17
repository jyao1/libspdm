/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_auth_device_secret_lib_internal.h"
#include "industry_standard/spdm_authorization.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

/*
 * In-memory queue for pending authorization events.
 *
 * Wire format for each queued entry (matches libspdm_parse_and_send_event):
 *   uint32_t event_instance_id
 *   uint32_t reserved
 *   uint8_t  svh_id          (SPDM_REGISTRY_ID_DMTF_DSP = 0x0b)
 *   uint8_t  svh_vendor_id_len (2)
 *   uint16_t svh_vendor_id   (SPDM_AUTH_EVENT_GROUP_VENDOR_ID = 289)
 *   uint16_t event_type_id
 *   uint16_t event_detail_len
 *   uint8_t  event_detail[event_detail_len]
 */

#define AUTH_EVENT_QUEUE_MAX 8
#define AUTH_EVENT_BUF_MAX   256

typedef struct {
    uint8_t  data[AUTH_EVENT_BUF_MAX];
    size_t   size;
} auth_event_entry_t;

static auth_event_entry_t g_auth_event_queue[AUTH_EVENT_QUEUE_MAX];
static uint32_t           g_auth_event_count   = 0;
static uint32_t           g_auth_event_next_id = 1; /* monotonic instance counter */

static void auth_event_queue_push(uint16_t event_type_id,
                                   const void *event_detail,
                                   uint16_t event_detail_len)
{
    uint8_t *p;
    auth_event_entry_t *entry;

    if (g_auth_event_count >= AUTH_EVENT_QUEUE_MAX) {
        return; /* queue full – drop */
    }

    entry = &g_auth_event_queue[g_auth_event_count];
    p = entry->data;

    /* event_instance_id (4) */
    p[0] = (uint8_t)(g_auth_event_next_id);
    p[1] = (uint8_t)(g_auth_event_next_id >> 8);
    p[2] = (uint8_t)(g_auth_event_next_id >> 16);
    p[3] = (uint8_t)(g_auth_event_next_id >> 24);
    g_auth_event_next_id++;
    p += 4;

    /* reserved (4) */
    p[0] = p[1] = p[2] = p[3] = 0;
    p += 4;

    /* svh_id */
    *p++ = SPDM_REGISTRY_ID_DMTF_DSP;  /* 0x0b */

    /* svh_vendor_id_len */
    *p++ = 2;

    /* svh_vendor_id: SPDM_AUTH_EVENT_GROUP_VENDOR_ID = 289 (0x0121), little-endian */
    p[0] = (uint8_t)((SPDM_AUTH_EVENT_GROUP_VENDOR_ID) & 0xFF);
    p[1] = (uint8_t)((SPDM_AUTH_EVENT_GROUP_VENDOR_ID >> 8) & 0xFF);
    p += 2;

    /* event_type_id (2) */
    p[0] = (uint8_t)(event_type_id);
    p[1] = (uint8_t)(event_type_id >> 8);
    p += 2;

    /* event_detail_len (2) */
    p[0] = (uint8_t)(event_detail_len);
    p[1] = (uint8_t)(event_detail_len >> 8);
    p += 2;

    /* event_detail */
    if (event_detail_len > 0 && event_detail != NULL) {
        libspdm_copy_mem(p, AUTH_EVENT_BUF_MAX - (size_t)(p - entry->data),
                         event_detail, event_detail_len);
        p += event_detail_len;
    }

    entry->size = (size_t)(p - entry->data);
    g_auth_event_count++;
}

/*
 * Called by the responder library after a successful SET_CRED_ID_PARAMS.
 * Queues a CredIDparamsChanged event (EventTypeId = 1).
 */
void libspdm_auth_device_notify_cred_id_params_changed(
    void *spdm_context, uint32_t session_id, uint16_t credential_id)
{
    uint8_t buf[sizeof(spdm_auth_event_cred_id_params_changed_t) + sizeof(uint16_t)];
    spdm_auth_event_cred_id_params_changed_t *hdr;
    uint16_t *id_list;

    (void)spdm_context;
    (void)session_id;

    hdr = (spdm_auth_event_cred_id_params_changed_t *)buf;
    hdr->credential_id_count = 1;
    id_list = (uint16_t *)(buf + sizeof(*hdr));
    id_list[0] = credential_id;

    auth_event_queue_push(SPDM_AUTH_EVENT_TYPE_CRED_ID_PARAMS_CHANGED,
                          buf,
                          (uint16_t)sizeof(buf));
}

/*
 * Called by the responder library after a successful SET_AUTH_POLICY.
 * Queues an AuthPolicyChanged event (EventTypeId = 2).
 */
void libspdm_auth_device_notify_auth_policy_changed(
    void *spdm_context, uint32_t session_id, uint16_t credential_id,
    const spdm_svh_dmtf_dsp_header_t *policy_owner_id,
    uint16_t policy_id_len, const uint8_t *policy_id)
{
    uint8_t buf[sizeof(spdm_auth_event_auth_policy_changed_t) + 128];
    spdm_auth_event_auth_policy_changed_t *hdr = (spdm_auth_event_auth_policy_changed_t *)buf;
    uint16_t total_len;

    (void)spdm_context;
    (void)session_id;

    total_len = (uint16_t)(sizeof(spdm_auth_event_auth_policy_changed_t) + policy_id_len);
    if (total_len > sizeof(buf)) {
        total_len = (uint16_t)sizeof(buf);
        policy_id_len = (uint16_t)(sizeof(buf) - sizeof(spdm_auth_event_auth_policy_changed_t));
    }

    hdr->credential_id = credential_id;
    if (policy_owner_id != NULL) {
        libspdm_copy_mem(&hdr->policy_owner_id, sizeof(hdr->policy_owner_id),
                         policy_owner_id, sizeof(*policy_owner_id));
    } else {
        libspdm_zero_mem(&hdr->policy_owner_id, sizeof(hdr->policy_owner_id));
    }
    hdr->policy_id_len = policy_id_len;
    if (policy_id_len > 0 && policy_id != NULL) {
        libspdm_copy_mem(buf + sizeof(spdm_auth_event_auth_policy_changed_t),
                         sizeof(buf) - sizeof(spdm_auth_event_auth_policy_changed_t),
                         policy_id, policy_id_len);
    }

    auth_event_queue_push(SPDM_AUTH_EVENT_TYPE_AUTH_POLICY_CHANGED, buf, total_len);
}

/*
 * Called by libspdm_generate_event_list (in spdm_device_secret_lib_sample/event.c)
 * to drain the pending authorization event queue.
 *
 * events_list_size is in/out: on input it is the available buffer; on output
 * it is the number of bytes actually written.
 *
 * The queue is consumed (cleared) after this call so each event is
 * delivered exactly once.
 */
bool libspdm_auth_event_drain(
    uint32_t *event_count,
    size_t *events_list_size,
    void *events_list)
{
    uint8_t *out = (uint8_t *)events_list;
    size_t   remaining = *events_list_size;
    uint32_t count = 0;
    uint32_t i;

    for (i = 0; i < g_auth_event_count; i++) {
        if (g_auth_event_queue[i].size > remaining) {
            break; /* not enough space */
        }
        libspdm_copy_mem(out, remaining,
                         g_auth_event_queue[i].data,
                         g_auth_event_queue[i].size);
        out       += g_auth_event_queue[i].size;
        remaining -= g_auth_event_queue[i].size;
        count++;
    }

    *event_count      = count;
    *events_list_size = (size_t)(out - (uint8_t *)events_list);

    /* consume delivered events */
    g_auth_event_count = 0;

    return (count > 0);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
