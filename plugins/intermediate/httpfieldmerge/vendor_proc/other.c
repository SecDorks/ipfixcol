/*
 * \file vendor_proc/other.c
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
#include "field_mappings.h"
#include "other.h"

/**
 * \brief Retrieves a reference to a set of enterprise-specific fields,
 * based on a supplied PEN.
 *
 * \param[in] pen IANA Private Enterprise Number
 * \return Field reference if supplied PEN is known, NULL otherwise
 */
static struct ipfix_entity* pen_to_enterprise_fields(uint32_t pen)
{
    struct ipfix_entity *fields = NULL;
    switch (pen) {
        case CISCO_PEN:     fields = (struct ipfix_entity *) cisco_fields;
                            break;

        case MASARYK_PEN:   fields = (struct ipfix_entity *) masaryk_fields;
                            break;

        case NTOP_PEN:      fields = (struct ipfix_entity *) ntop_fields;
                            break;

        case INVEA_PEN:     fields = (struct ipfix_entity *) invea_fields;
                            break;

        case RS_PEN:        fields = (struct ipfix_entity *) rs_fields;
                            break;

        default:            MSG_WARNING(msg_module, "Could not retrieve enterprise-specific IEs; unknown PEN (%u)", pen);
                            break;
    }

    return fields;
}

/**
 * \brief Retrieves a reference to field mappings, based on a supplied PEN.
 *
 * \param[in] pen IANA Private Enterprise Number
 * \return Field mappings reference if supplied PEN is known, NULL otherwise
 */
static struct field_mapping* pen_to_field_mappings(uint32_t pen)
{
    struct field_mapping *mapping = NULL;
    switch (pen) {
        case MASARYK_PEN:   mapping = (struct field_mapping *) masaryk_field_mappings;
                            break;

        case NTOP_PEN:      mapping = (struct field_mapping *) ntop_field_mappings;
                            break;

        case INVEA_PEN:     mapping = (struct field_mapping *) invea_field_mappings;
                            break;

        case RS_PEN:        mapping = (struct field_mapping *) rs_field_mappings;
                            break;

        default:            MSG_WARNING(msg_module, "Could not retrieve field mappings for enterprise-specific IEs; unknown PEN (%u)", pen);
                            break;
    }

    return mapping;
}

/**
 * \brief Retrieves a reference to field mappings, based on a field ID. This is
 * only for fields converted from NetFlow v9 that have an 'all-ones' enterprise ID.
 *
 * \param[in] id Field ID
 * \return Field mappings reference if ID could be found, NULL otherwise
 */
static struct field_mapping* get_field_mappings_v9(uint16_t id)
{
    struct field_mapping *mapping = NULL;
    uint8_t i;

    for (i = 0; i < ntop_field_count && mapping == NULL; ++i) {
        if (ntopv9_field_mappings[i].from.pen == NFV9_CONVERSION_PEN && ntopv9_field_mappings[i].from.element_id == id) {
            mapping = &ntopv9_field_mappings[i];
        }
    }

    // if (mapping == NULL) {
    //     MSG_WARNING(msg_module, "Could not retrieve (NetFlow v9) field mappings for enterprise-specific IEs; unknown field ID (%u)", id);
    // }

    return mapping;
}

/**
 * \brief Retrieves an IPFIX Information Element based on a supplied field
 * mapping and the mapping's source field. As such, the target of a mapping
 * is retrieved.
 *
 * \param[in] mapping Field mapping
 * \param[in] source_field Source field of the mapping, for which the target
 *      field must be retrieved
 * \return Field reference if the supplied source field is known within the
 *      supplied mapping, NULL otherwise
 */
static struct ipfix_entity* field_to_mapping_target(struct field_mapping* mapping, struct ipfix_entity* source_field)
{
    uint8_t i;
    for (i = 0; i < vendor_fields_count; ++i) {
        if (mapping[i].from.element_id == source_field->element_id) {
            return &mapping[i].to;
        }
    }

    return NULL;
}

/**
 * \brief Processing of template records and option template records
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void other_template_rec_processor(uint8_t *rec, int rec_len, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;
    struct ipfix_template_record *old_rec = (struct ipfix_template_record *) rec;
    struct ipfix_template_record *new_rec;
    uint16_t templ_id = ntohs(old_rec->template_id);
    uint8_t i;

    /* Don't process options template records */
    if (proc->type == TM_OPTIONS_TEMPLATE) {
        /* Copy record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /* Prepare hashmap lookup key */
    struct templ_stats_key_t *templ_stats_key = calloc(1, proc->plugin_conf->templ_stats_key_len);
    if (!templ_stats_key) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return;
    }

    /* Set key values */
    templ_stats_key->od_id = proc->odid;
    templ_stats_key->ip_id = proc->plugin_conf->ip_id;
    templ_stats_key->templ_id = templ_id;

    /* Get structure from hashmap that provides information about current template */
    struct templ_stats_elem_t *templ_stats;
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &templ_stats_key->od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    if (templ_stats == NULL) {
        MSG_ERROR(msg_module, "Could not find key <%u, %u, %u> in hashmap; using original template",
                templ_stats_key->od_id,
                templ_stats_key->ip_id,
                templ_stats_key->templ_id);

        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;

        free(templ_stats_key);
        return;
    }

    free(templ_stats_key);

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

    /* Find HTTP fields (if present) and replace them */
    struct field_mapping *field_mappings;
    struct ipfix_entity *target_field;
    uint16_t count = 0, index = 0;
    uint16_t field_id;

    if (templ_stats->http_fields_pen == NFV9_CONVERSION_PEN) {
        for (i = 0; i < vendor_fields_count; ++i) {
            /* Iterate over all fields in template record */
            while (count < ntohs(new_rec->count)
                    && (uint8_t *) &new_rec->fields[index] - (uint8_t *) new_rec < rec_len) {
                field_id = ntohs(new_rec->fields[index].ie.id);

                /* Only continue if enterprise bit is set */
                if (field_id & 0x8000) {
                    /* Unset enterprise bit */
                    field_id &= ~0x8000;

                    /* Retrieve field mapping */
                    field_mappings = get_field_mappings_v9(field_id);
                    if (field_mappings) {
                        /* Find mapping's target field */
                        target_field = field_to_mapping_target(field_mappings, &field_mappings[i].from);

                        /* Replace field ID */
                        new_rec->fields[index].ie.id = htons(target_field->element_id | 0x8000);

                        /* PEN comes just after the IE, before the next IE */
                        ++index;

                        /* Replace PEN */
                        new_rec->fields[index].enterprise_number = htonl(target_field->pen);
                    } else {
                        /* No field mappings found, so no need to translate field ID */
                        /* PEN comes just after the IE, before the next IE */
                        ++index;
                    }
                }

                ++count;
                ++index;
            }
        }
    } else {
        struct ipfix_entity *http_fields = pen_to_enterprise_fields(templ_stats->http_fields_pen);
        if ((field_mappings = pen_to_field_mappings(templ_stats->http_fields_pen))) {
            /* Iterate over all fields in template record */
            while (count < ntohs(new_rec->count)
                    && (uint8_t *) &new_rec->fields[index] - (uint8_t *) new_rec < rec_len) {
                field_id = ntohs(new_rec->fields[index].ie.id);

                /* Only continue if enterprise bit is set */
                if (field_id & 0x8000) {
                    /* Unset enterprise bit */
                    field_id &= ~0x8000;

                    for (i = 0; i < vendor_fields_count; ++i) {
                        /* Apply field mapping if enterprise-specific fields have been found */
                        /* Note: we can safely use 'index + 1' in the statement below, since the first part
                         * of the condition already indicates that we are dealing with an enterprise-specific IE
                         */
                        if (field_id == http_fields[i].element_id && ntohl(new_rec->fields[index + 1].enterprise_number) == http_fields[i].pen) {
                            /* Find mapping's target field */
                            target_field = field_to_mapping_target(field_mappings, &http_fields[i]);

                            /* Replace field ID */
                            new_rec->fields[index].ie.id = htons(target_field->element_id | 0x8000);

                            /* PEN comes just after the IE, before the next IE */
                            ++index;

                            /* Replace PEN */
                            new_rec->fields[index].enterprise_number = htonl(target_field->pen);

                            /* No need to loop further since field has been found already */
                            break;
                        }
                    }
                }

                ++count;
                ++index;
            }
        }
    }

    /* Store it in template manager */
    proc->key->tid = templ_id;

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
void other_data_rec_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
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

    /* Copy original data record */
    memcpy(proc->msg + proc->offset, rec, rec_len);
    proc->offset += rec_len;
    proc->length += rec_len;
}
