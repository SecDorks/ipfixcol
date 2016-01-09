/*
 * \file vendor_proc/cisco.c
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
 * Copyright (c) 2015 Secdorks.net
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
#include "cisco.h"
#include "fields.h"

/**
 * \brief Processing of template records and option template records
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void cisco_template_rec_processor(uint8_t *rec, int rec_len, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;
    struct ipfix_template_record *old_rec = (struct ipfix_template_record *) rec;
    struct ipfix_template_record *new_rec;

    /* Don't process options template records */
    if (proc->type == TM_OPTIONS_TEMPLATE) {
        /* Copy record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /* Get structure from hashmap that provides information about current template */
    struct templ_stats_elem_t *templ_stats;
    uint16_t template_id = ntohs(old_rec->template_id);
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &template_id, sizeof(uint16_t), templ_stats);
    if (templ_stats == NULL) {
        MSG_ERROR(msg_module, "Could not find key '%u' in hashmap; using original template", template_id);

        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /*
     * Skip further processing in any of the following situations:
     *      - Template does not include HTTP IEs (hostname, URL)
     *      - Template already uses the unified set of HTTP IEs
     */
    if (templ_stats->http_fields_pen == 0 || templ_stats->http_fields_pen == TARGET_PEN) {
        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /* Replace enterprise-specific fields by vendors with 'unified' fields */
    /* Copy original template record */
    new_rec = calloc(1, rec_len);
    if (!new_rec) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return;
    }

    memcpy(new_rec, old_rec, rec_len);

    /* Count number of field occurences */
    int http_field_count = template_record_count_field_occurences(new_rec, CISCO_PEN, 12235);
    if (http_field_count != 4) {
        MSG_WARNING(msg_module, "Template record features unexpected number of instances of field e%uid12235 (expected: %d, actual: %d)", CISCO_PEN, 4, http_field_count);

        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, new_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        free(new_rec);
        return;
    }

    uint8_t http_instance = 1;
    uint16_t count = 0, index = 0;
    uint16_t id;
    while (count < ntohs(new_rec->count)
            && (uint8_t *) &new_rec->fields[index] - (uint8_t *) new_rec < rec_len
            && http_instance <= http_field_count) {
        id = ntohs(new_rec->fields[index].ie.id);

        /* Only continue if enterprise bit is set */
        if (id & 0x8000) {
            /* Unset enterprise bit */
            id &= ~0x8000;

            /* Apply field mapping if enterprise-specific fields have been found */
            /* Note: we can safely use 'index + 1' in the statement below, since the first part
             * of the condition already indicates that we are dealing with an enterprise-specific IE
             */
            if (id == 12235 && ntohl(new_rec->fields[index + 1].enterprise_number) == CISCO_PEN) {
                /* Determine target field */
                /* Cisco uses multiple instances (4) of field e9id12235 for exporting
                   HTTP-related information, always in the following order:
                        - Instance 1: URL
                        - Instance 2: hostname
                        - Instance 3: user agent string
                        - Instance 4: unknown?
                 */
                uint32_t id;
                switch (http_instance) {
                    case 1:     id = ((struct ipfix_entity) target_http_url).element_id;
                                break;

                    case 2:     id = ((struct ipfix_entity) target_http_hostname).element_id;
                                break;

                    case 3:     id = ((struct ipfix_entity) target_http_user_agent).element_id;
                                break;

                    default:    id = ((struct ipfix_entity) target_unknown).element_id;
                                break;
                }

                /* Replace field ID */
                new_rec->fields[index].ie.id = htons(id | 0x8000);

                /* PEN comes just after the IE, before the next IE */
                ++index;

                /* Replace PEN */
                new_rec->fields[index].enterprise_number = htonl(TARGET_PEN);

                ++http_instance;
            }
        }

        ++count;
        ++index;
    }

    /* Store it in template manager */
    proc->key->tid = template_id;

    if (tm_get_template(proc->plugin_conf->tm, proc->key) == NULL) {
        if (tm_add_template(proc->plugin_conf->tm, (void *) new_rec, TEMPL_MAX_LEN, proc->type, proc->key) == NULL) {
            MSG_ERROR(msg_module, "[%u] Failed to add template to template manager (template ID: %u)", proc->key->odid, proc->key->tid);
        }
    } else {
        if (tm_update_template(proc->plugin_conf->tm, (void *) new_rec, TEMPL_MAX_LEN, proc->type, proc->key) == NULL) {
            MSG_ERROR(msg_module, "[%u] Failed to update template in template manager (template ID: %u)", proc->key->odid, proc->key->tid);
        }
    }

    /* Add new record to message */
    memcpy(proc->msg + proc->offset, new_rec, rec_len);
    proc->offset += rec_len;
    proc->length += rec_len;

    /* Add new template (ID) to hashmap (templ_stats), with same information as 'old' template (ID) */
    struct templ_stats_elem_t *templ_stats_new;
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &template_id, sizeof(uint16_t), templ_stats_new);
    if (!templ_stats_new) {
        templ_stats_new = calloc(1, sizeof(struct templ_stats_elem_t));
        if (!templ_stats_new) {
            MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            free(new_rec);
            return;
        }

        templ_stats_new->id = template_id;
        templ_stats_new->http_fields_pen = TARGET_PEN;
        templ_stats_new->http_fields_pen_determined = templ_stats->http_fields_pen_determined;
        HASH_ADD(hh, proc->plugin_conf->templ_stats, id, sizeof(uint16_t), templ_stats_new);
    }

    free(new_rec);
}

/**
 * \brief Processing of data records
 *
 * \param[in] rec Pointer to data record
 * \param[in] rec_len Data record length
 * \param[in] templ IPFIX template corresponding to the data record
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void cisco_data_rec_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;

    /* Check whether we will exceed the allocated memory boundary */
    if (proc->offset + rec_len > proc->allocated_msg_len) {
        proc->allocated_msg_len = proc->allocated_msg_len + 100;
        proc->msg = realloc(proc->msg, proc->allocated_msg_len);
        if (!proc->msg) {
            MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }
    }

    /* Strip first six bytes from Cisco HTTP fields, as they are used for some Cisco-proprietary
     * encoding and not part of the actual exported HTTP-related string
     */
    int field_len, field_offset;
    uint8_t i;
    uint16_t new_field_len;
    for (i = 0; i < target_field_count; ++i) {
        field_offset = data_record_field_offset(rec, templ, target_fields[i].pen, target_fields[i].element_id, &field_len);

        /* Remove first six bytes from fields */
        memmove(rec + field_offset, rec + field_offset + 6, rec_len - field_offset - 6);

        /* Update field length */
        new_field_len = field_len - 6;

        /* Update field length in IPFIX message */
        if (new_field_len >= 255) {
            /* Set new (variable) length in byte two and three of field. Note that
             * 'field_offset' contains the offset to the actual data, so the field
             * length is stored at 'field_offset - 2'.
             */
            new_field_len = htons(new_field_len);
            memcpy(rec + field_offset - 2, &new_field_len, sizeof(new_field_len));
        } else if (new_field_len < 255 && field_len >= 255) {
            /* The second and third byte of the field must be removed, since the (new) field
             * length is < 255 and can therefore be stored in the first byte
             */
            memmove(rec + field_offset - 2, rec + field_offset, new_field_len);
            field_offset -= 2;
            memset(rec + field_offset - 1, new_field_len, 1);
        } else {
            /* Set new (variable) length in first byte of field. Note that 'field_offset'
             * contains the offset to the actual data, so the field length is stored at
             * 'field_offset - 1'
             */
            memset(rec + field_offset - 1, new_field_len, 1);
        }

        /* Update record length */
        rec_len -= 6;
    }

    /* Add new record to message */
    memcpy(proc->msg + proc->offset, rec, rec_len);
    proc->offset += rec_len;
    proc->length += rec_len;
}
