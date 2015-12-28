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
 * \brief Count the number of occurrences of the specified field
 * \param[in] rec Template record
 * \param[in] enterprise Field enterprise ID
 * \param[in] id Field ID
 * \return Number of field occurrences
 */
int template_record_count_field_occurences(struct ipfix_template_record *rec, uint32_t enterprise, uint16_t id)
{
    int field_count = 0;
    uint16_t total_field_count = ntohs(rec->count);

    struct ipfix_template_row *row = (struct ipfix_template_row *) rec->fields;

    int i;
    for (i = 0; i < total_field_count; ++i, ++row) {
        uint16_t rid = ntohs(row->id);
        uint32_t ren = 0;

        /* Get field ID and enterprise number */
        if (rid >> 15) {
            rid = rid & 0x7FFF;
            ++row;
            ren = ntohl(*((uint32_t *) row));
        }

        /* Check informations */
        if (rid == id && ren == enterprise) {
            if (ren != 0) {
                --row;
            }

            ++field_count;
        }
    }

    return field_count;
}

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
    MSG_DEBUG(msg_module, " > Detected %d Cisco HTTP fields", http_field_count);
    if (http_field_count != 4) {
        MSG_WARNING(msg_module, "Template record features unexpected number of enterprise specific fields (expected: %d, actual: %d)", http_field_count);

        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, new_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    uint8_t http_field_instance = 1;
    uint16_t count = 0, index = 0;
    uint16_t field_id;
    while (count < ntohs(new_rec->count)
            && (uint8_t *) &new_rec->fields[index] - (uint8_t *) new_rec < rec_len
            && http_field_instance <= http_field_count) {
        field_id = ntohs(new_rec->fields[index].ie.id);

        /* Only continue if enterprise bit is set */
        if (field_id & 0x8000) {
            /* Unset enterprise bit */
            field_id &= ~0x8000;

            /* Apply field mapping if enterprise-specific fields have been found */
            /* Note: we can safely use 'index + 1' in the statement below, since the first part
             * of the condition already indicates that we are dealing with an enterprise-specific IE
             */
            if (field_id == 12235 && ntohl(new_rec->fields[index + 1].enterprise_number) == CISCO_PEN) {
                /* Determine target field */
                /* Cisco uses multiple instances (4) of field e9id12235 for exporting
                   HTTP-related information, always in the following order:
                        - Instance 1: URL
                        - Instance 2: hostname
                        - Instance 3: user agent string
                        - Instance 4: unknown?
                 */
                struct ipfix_entity target_field;
                switch (http_field_instance) {
                    case 1:     target_field = target_http_url;
                                break;

                    case 2:     target_field = target_http_hostname;
                                break;

                    case 3:     target_field = target_http_user_agent;
                                break;

                    default:    target_field = target_unknown;
                                break;
                }

                if (target_field.pen == target_unknown.pen && target_field.element_id == target_unknown.element_id) {
                    /* Remove field from template record (8 = IE size, including PEN) */
                    memmove(&(new_rec->fields[index].ie), &(new_rec->fields[index].ie) + 8, rec_len - ((uint8_t *) &(new_rec->fields[index].ie) - rec));

                    /* Housekeeping to make sure that loop continues correctly */
                    rec_len -= 8;
                    --count;
                    --index;

                    /* Template record features one field less */
                    new_rec->count = htons(ntohs(new_rec->count) - 1);
                } else {
                    /* Replace field ID */
                    new_rec->fields[index].ie.id = htons(target_field.element_id | 0x8000);

                    /* PEN comes just after the IE, before the next IE */
                    ++index;

                    /* Replace PEN */
                    new_rec->fields[index].enterprise_number = htonl(target_field.pen);
                }

                ++http_field_instance;
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
 * \param[in] data Any-type data structure (here: proxy_processor)
 */
void cisco_data_rec_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
{
    (void) rec;
    (void) rec_len;
    (void) templ;
    (void) data;
}
