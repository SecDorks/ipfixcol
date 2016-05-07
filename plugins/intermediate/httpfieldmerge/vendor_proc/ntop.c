/*
 * \file vendor_proc/ntop.c
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'httpfieldmerge' intermediate plugin.
 *
 * Intermediate plugin for IPFIXcol that merges HTTP-related fields from various vendors
 * into one unified set, such that analysis applications can always rely on the unified
 * set of fields. The following fields are currently supported:
 *
 *     - HTTP hostname
 *     - HTTP URL
 *     - HTTP user agent (UA)
 *
 * Specifically, this plugin performs only a single task:
 *
 *     - Replace the IE definitions of HTTP-related fields with those of the unified
 *          set of fields. As such, only templates are modified (and data records are
 *          not).
 *
 * HTTP-related fields from the following vendors are currently supported:
 *
 *     - Cisco,                 PEN: 9
 *     - Masaryk University,    PEN: 16982
 *     - INVEA-TECH,            PEN: 39499
 *     - ntop,                  PEN: 35632
 *
 * The unified set of fields uses PEN '44913'.
 *
 * Copyright (c) 2016 Secdorks.net
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is, and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include "httpfieldmerge.h"
#include "ntop.h"
#include "fields.h"

/**
 * \brief Processing of data records
 *
 * \param[in] rec Pointer to data record
 * \param[in] rec_len Data record length
 * \param[in] templ IPFIX template corresponding to the data record
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void ntop_data_rec_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;
    (void) templ;

    /* Check whether we will exceed the allocated memory boundary */
    if (proc->offset + rec_len > proc->allocated_msg_len) {
        proc->allocated_msg_len = proc->allocated_msg_len + 100;
        proc->msg = realloc(proc->msg, proc->allocated_msg_len);
        if (!proc->msg) {
            MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }
    }

    /* Strip hostname from URL field */
    int hostname_field_len = 0, url_field_len;
    data_record_field_offset(rec, templ, TARGET_PEN, ((struct ipfix_entity) target_http_hostname).element_id, &hostname_field_len);
    if (hostname_field_len == 0) {
        /* Copy original data record */
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    int url_field_offset = data_record_field_offset(rec, templ, TARGET_PEN, ((struct ipfix_entity) target_http_url).element_id, &url_field_len);
    uint16_t new_url_field_len = url_field_len - hostname_field_len;

    // MSG_DEBUG(msg_module, " > Hostname field len (e%uid%u): %d", TARGET_PEN, ((struct ipfix_entity) target_http_hostname).element_id, hostname_field_len);

    /* Determine URL field based on template */
    int url_field_templ_len = template_get_field_length(templ, TARGET_PEN, ((struct ipfix_entity) target_http_url).element_id | 0x8000);
    if (url_field_templ_len == VAR_IE_LENGTH) {
        /* Move URL by 'hostname_field_len' bytes, effectively removing the hostname component */
        memmove(rec + url_field_offset, rec + url_field_offset + hostname_field_len, rec_len - url_field_offset - hostname_field_len);

        /* Update field length in IPFIX message */
        if (new_url_field_len >= 255) {
            /* Set new (variable) length in byte two and three of field. Note that
             * 'url_field_offset' contains the offset to the actual data, so the field
             * length is stored at 'url_field_offset - 2'.
             */
            new_url_field_len = htons(new_url_field_len);
            memcpy(rec + url_field_offset - 2, &new_url_field_len, sizeof(new_url_field_len));
        } else if (new_url_field_len < 255 && url_field_len >= 255) {
            /* The second and third byte of the field must be removed, since the (new) field
             * length is < 255 and can therefore be stored in the first byte
             */
            memmove(rec + url_field_offset - 2, rec + url_field_offset, new_url_field_len);
            url_field_offset -= 2;
            memset(rec + url_field_offset - 1, new_url_field_len, 1);
        } else {
            /* Set new (variable) length in first byte of field. Note that 'url_field_offset'
             * contains the offset to the actual data, so the field length is stored at
             * 'url_field_offset - 1'
             */
            memset(rec + url_field_offset - 1, new_url_field_len, 1);
        }
    } else if (url_field_templ_len == -1) { /* Field has fixed length specified in template */
        MSG_ERROR(msg_module, "Field e%uid%u not found in template; cannot determine field length", TARGET_PEN, ((struct ipfix_entity) target_http_url).element_id);

        /* Copy original data record */
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    } else { /* Field has fixed length specified in template */
        /* Move URL by 'hostname_field_len' bytes, effectively removing the hostname component */
        memmove(rec + url_field_offset, rec + url_field_offset + hostname_field_len, rec_len - url_field_offset - hostname_field_len);

        /* Zero out the (now unused) bytes that were used for storing the URL */
        memset(rec + new_url_field_len, 0, hostname_field_len);
    }

    rec_len -= hostname_field_len;

    /* Add new record to message */
    memcpy(proc->msg + proc->offset, rec, rec_len);
    proc->offset += rec_len;
    proc->length += rec_len;
}
