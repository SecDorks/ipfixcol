/*
 * \file httpfieldmerge.c
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'httpfieldmerge' intermediate plugin.
 *
 * Intermediate plugin for IPFIXcol that merges HTTP-related fields from various vendors
 * into one unified set, such that analysis applications can always rely on the unified
 * set of fields. The following fields are currently supported:
 *
 *     - HTTP hostname
 *     - HTTP URL
 *     - HTTP User Agent
 *
 * Specifically, this plugin performs only a single task:
 *
 *     - Replace the IE definitions of HTTP-related fields with those of the unified
 *          set of fields. As such, only templates are modified (and data records are
 *          not).
 *
 * HTTP-related fields from the following vendors are currently supported:
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httpfieldmerge.h"

/* API version constant */
IPFIXCOL_API_VERSION;

/* Identifier for MSG_* macros */
static char *msg_module = "httpfieldmerge";

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

    for (i = 0; i < vendor_fields_count && mapping == NULL; ++i) {
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
 * \brief Determines whether template contains HTTP-related fields.
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void templates_stat_processor(uint8_t *rec, int rec_len, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;
    struct ipfix_template_record *record = (struct ipfix_template_record *) rec;
    (void) rec_len;
    int i;

    /* Determine IP versions used within this template */
    struct templ_stats_elem_t *templ_stats;
    uint16_t template_id = ntohs(record->template_id);
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &template_id, sizeof(uint16_t), templ_stats);
    if (templ_stats == NULL) { /* Do only if it was not done (successfully) before */
        templ_stats = calloc(1, sizeof(struct templ_stats_elem_t));
        if (!templ_stats) {
            MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }

        templ_stats->id = template_id;
        templ_stats->http_fields_pen = 0;
        templ_stats->http_fields_pen_determined = 0;

        /* Store result in hashmap */
        HASH_ADD(hh, proc->plugin_conf->templ_stats, id, sizeof(uint16_t), templ_stats);
    }

    /* Determine exporter PEN based on presence of certain enterprise-specific IEs */
    if (templ_stats->http_fields_pen_determined == 0) { /* Do only if it was not done (successfully) before */
        /* Check enterprise-specific IEs from INVEA-TECH */
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, invea_fields[i].pen, invea_fields[i].element_id, NULL) != NULL) {
                MSG_INFO(msg_module, "[%u] Detected enterprise-specific IEs (HTTP) from INVEA-TECH in template (template ID: %u)", proc->odid, template_id);
                templ_stats->http_fields_pen = invea_fields[i].pen;
            }
        }

        /* Check enterprise-specific IEs from ntop */
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, ntop_fields[i].pen, ntop_fields[i].element_id, NULL) != NULL) {
                MSG_INFO(msg_module, "[%u] Detected enterprise-specific IEs (HTTP) from ntop in template (template ID: %u)", proc->odid, template_id);
                templ_stats->http_fields_pen = ntop_fields[i].pen;
            }
        }

        /* Check enterprise-specific IEs from ntop (converted from NetFlow v9)
         * https://github.com/CESNET/ipfixcol/issues/16
         * http://www.ietf.org/mail-archive/web/ipfix/current/msg07287.html
         */
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, NFV9_CONVERSION_PEN, ntopv9_fields[i].element_id, NULL) != NULL) {
                MSG_INFO(msg_module, "[%u] Detected enterprise-specific HTTP IEs from ntop (NFv9) in template (template ID: %u)", proc->odid, template_id);
                templ_stats->http_fields_pen = NFV9_CONVERSION_PEN;
            }
        }

        /* Check enterprise-specific IEs from Masaryk University */
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, masaryk_fields[i].pen, masaryk_fields[i].element_id, NULL) != NULL) {
                MSG_INFO(msg_module, "[%u] Detected enterprise-specific IEs (HTTP) from Masaryk University in template (template ID: %u)", proc->odid, template_id);
                templ_stats->http_fields_pen = masaryk_fields[i].pen;
            }
        }

        /* Check enterprise-specific IEs from RS */
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, rs_fields[i].pen, rs_fields[i].element_id, NULL) != NULL) {
                MSG_INFO(msg_module, "[%u] Detected enterprise-specific IEs (HTTP) from RS in template (template ID: %u)", proc->odid, template_id);
                templ_stats->http_fields_pen = rs_fields[i].pen;
            }
        }

        templ_stats->http_fields_pen_determined = 1;
    }
}

/**
 * \brief Processing of template records and option template records
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void templates_processor(uint8_t *rec, int rec_len, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;
    struct ipfix_template_record *old_rec = (struct ipfix_template_record *) rec;
    struct ipfix_template_record *new_rec;
    uint8_t i;

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
     * Skip further processing if template does not include HTTP IEs (hostname, URL),
     * or if template already uses the unified set of HTTP IEs.
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
 * \param[in] data Any-type data structure (here: proxy_processor)
 */
void data_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
{
    struct httpfieldmerge_processor *proc = (struct httpfieldmerge_processor *) data;
    (void) templ;

    /* Check whether we will exceed the allocated memory boundary */
    if (proc->offset + rec_len > proc->allocated_msg_length) {
        MSG_ERROR(msg_module, "Not enough memory allocated for processing full message (allocated: %u, current offset: %u)",
                proc->allocated_msg_length, proc->offset);
        return;
    }

    /* Copy original data record */
    memcpy(proc->msg + proc->offset, rec, rec_len);
    proc->offset += rec_len;
    proc->length += rec_len;
}

/**
 *  \brief Initialize intermediate Plugin
 *
 * \param[in] params configuration xml for the plugin
 * \param[in] ip_config configuration structure of corresponding intermediate process
 * \param[in] ip_id source ID into template manager for creating templates
 * \param[in] template_mgr collector's Template Manager
 * \param[out] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_init(char *params, void *ip_config, uint32_t ip_id, struct ipfix_template_mgr *template_mgr, void **config)
{
    struct httpfieldmerge_config *conf;

    conf = (struct httpfieldmerge_config *) calloc(1, sizeof(*conf));
    if (!conf) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return -1;
    }

    conf->params = params;
    conf->ip_config = ip_config;
    conf->ip_id = ip_id;
    conf->tm = template_mgr;

    /* Initialize (empty) hashmap */
    conf->templ_stats = NULL;

    *config = conf;

    MSG_INFO(msg_module, "Plugin initialization completed successfully");

    /* Plugin successfully initialized */
    return 0;
}

/**
 *  \brief Initialize intermediate Plugin
 *
 * \param[in] params configuration xml for the plugin
 * \param[in] ip_config configuration structure of corresponding intermediate process
 * \param[in] ip_id source ID into template manager for creating templates
 * \param[in] template_mgr collector's Template Manager
 * \param[out] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_process_message(void *config, void *message)
{
    struct httpfieldmerge_config *conf;
    struct httpfieldmerge_processor proc;
    struct ipfix_message *msg, *new_msg;
    struct ipfix_template *templ, *new_templ;
    struct input_info_network *info;
    uint16_t prev_offset;
    uint32_t tsets = 0, otsets = 0;
    uint16_t i, new_i;

    conf = (struct httpfieldmerge_config *) config;
    msg = (struct ipfix_message *) message;
    info = (struct input_info_network *) msg->input_info;

    MSG_DEBUG(msg_module, "[%u] Received IPFIX message...", msg->input_info->odid);

    /* Check whether source was closed */
    if (msg->source_status == SOURCE_STATUS_CLOSED) {
        // MSG_WARNING(msg_module, "Source closed; skipping IPFIX message...");
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /*
     * Check whether this is an IPFIX message. Note that NetFlow v5/v9 and sFlow
     * packets are converted to IPFIX within the input plugins. Ignore this message
     * in case it is not an IPFIX message (v10).
     */
    if (msg->pkt_header->version != htons(IPFIX_VERSION)) {
        MSG_WARNING(msg_module, "[%u] Unexpected IPFIX version detected (%X); skipping IPFIX message...",
                msg->input_info->odid, msg->pkt_header->version);
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /*
     * Check for invalid message length (may be used as part of an attack). Please note:
     *      1) msg->pkt_header->length is uint16_t, which can never become more than MSG_MAX_LENGTH.
     *      2) We use '>=' in the comparison to avoid compiler warnings about the condition always being false.
     */
    uint16_t old_msg_length = ntohs(msg->pkt_header->length);
    if (old_msg_length >= MSG_MAX_LENGTH) {
        MSG_WARNING(msg_module, "[%u] Length of received IPFIX message is invalid (%X); skipping IPFIX message...",
                msg->input_info->odid, msg->pkt_header->length);
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /* Allocate memory for new message */
    uint16_t new_msg_length = old_msg_length;
    proc.allocated_msg_length = new_msg_length;
    proc.msg = calloc(1, new_msg_length);
    if (!proc.msg) {
        MSG_ERROR(msg_module, "Unable to allocate memory (%s:%d)", __FILE__, __LINE__);
        return 1;
    }

    /* Allocate memory for new IPFIX message */
    new_msg = calloc(1, sizeof(struct ipfix_message));
    if (!new_msg) {
        MSG_ERROR(msg_module, "Unable to allocate memory (%s:%d)", __FILE__, __LINE__);
        free(proc.msg);
        return 1;
    }

    /* Copy original IPFIX header */
    memcpy(proc.msg, msg->pkt_header, IPFIX_HEADER_LENGTH);
    new_msg->pkt_header = (struct ipfix_header *) proc.msg;
    proc.offset = IPFIX_HEADER_LENGTH;

    /* Initialize processing structure */
    proc.odid = msg->input_info->odid;
    proc.key = tm_key_create(info->odid, conf->ip_id, 0); /* Template ID (0) will be overwritten in a later stage */
    proc.plugin_conf = config;

    /* Process template sets */
    MSG_DEBUG(msg_module, "[%u] Processing template sets...", msg->input_info->odid);
    proc.type = TM_TEMPLATE;
    for (i = 0; i < MSG_MAX_TEMPL_SETS && msg->templ_set[i]; ++i) {
        prev_offset = proc.offset;

        /* Determine IP versions used within each template set and store result in hashmap. Also,
         * determine exporter PEN based on presence of certain enterprise-specific IEs.
         */
        template_set_process_records(msg->templ_set[i], proc.type, &templates_stat_processor, (void *) &proc);

        /* Add template set header, and update offset and length */
        memcpy(proc.msg + proc.offset, &(msg->templ_set[i]->header), 4);
        proc.offset += 4;
        proc.length = 4;

        /* Process all template set records */
        template_set_process_records(msg->templ_set[i], proc.type, &templates_processor, (void *) &proc);

        /* Check whether a new template set was added by 'templates_processor' */
        if (proc.offset == prev_offset + 4) { /* No new template set record was added */
            proc.offset = prev_offset;
        } else { /* New template set was added; add it to data structure as well */
            new_msg->templ_set[tsets] = (struct ipfix_template_set *) ((uint8_t *) proc.msg + prev_offset);
            new_msg->templ_set[tsets]->header.length = htons(proc.length);
            tsets++;
        }
    }

    /* Demarcate end of templates in set */
    new_msg->templ_set[tsets] = NULL;

    /* Process option template sets; only copy existing records */
    // MSG_DEBUG(msg_module, "Processing option template sets...");
    proc.type = TM_OPTIONS_TEMPLATE;
    for (i = 0; i < MSG_MAX_OTEMPL_SETS && msg->opt_templ_set[i]; ++i) {
        prev_offset = proc.offset;

        /* Add template set header, and update offset and length */
        memcpy(proc.msg + proc.offset, &(msg->opt_templ_set[i]->header), 4);
        proc.offset += 4;
        proc.length = 4;

        template_set_process_records((struct ipfix_template_set *) msg->opt_templ_set[i], proc.type, &templates_processor, (void *) &proc);

        /* Check whether a new options template set was added by 'templates_processor' */
        if (proc.offset == prev_offset + 4) {
            proc.offset = prev_offset;
        } else { /* New options template set was added; add it to data structure as well */
            new_msg->opt_templ_set[otsets] = (struct ipfix_options_template_set *) ((uint8_t *) proc.msg + prev_offset);
            new_msg->opt_templ_set[otsets]->header.length = htons(proc.length);
            otsets++;
        }
    }

    /* Demarcate end of option templates in set */
    new_msg->opt_templ_set[otsets] = NULL;

    /* Process data sets */
    MSG_DEBUG(msg_module, "[%u] Processing data sets...", msg->input_info->odid);
    for (i = 0, new_i = 0; i < MSG_MAX_DATA_COUPLES && msg->data_couple[i].data_set; ++i) {
        templ = msg->data_couple[i].data_template;

        /*
         * Skip processing in case there is no template available for this data set. This may
         * be caused by a problem in a previous intermediate plugin.
         */
        if (!templ) {
            MSG_WARNING(msg_module, "[%u] Data couple features no template (set: %u)", msg->input_info->odid, i);
            continue;
        }

        proc.key->tid = templ->template_id;
        new_templ = tm_get_template(conf->tm, proc.key);
        if (!new_templ) {
            // MSG_ERROR(msg_module, "Could not retrieve template from template manager (ODID: %u, IP ID: %u, template ID: %u)", info->odid, conf->ip_id, templ->template_id);
            /* Assume that template was not modified by this plugin if new template was not registered in template manager */
            new_templ = templ;
        }

        /* Add data set header, and update offset and length */
        memcpy(proc.msg + proc.offset, &(msg->data_couple[i].data_set->header), 4);
        proc.offset += 4;
        proc.length = 4;

        /* Update 'data_couple' by adjusting pointers to updated data structures */
        new_msg->data_couple[new_i].data_set = ((struct ipfix_data_set *) ((uint8_t *) proc.msg + proc.offset - 4));
        new_msg->data_couple[new_i].data_template = new_templ;

        /* Increase number of references to template */
        new_templ->last_message = templ->last_message;
        new_templ->last_transmission = templ->last_transmission;
        tm_template_reference_inc(new_templ);

        data_set_process_records(msg->data_couple[i].data_set, templ, &data_processor, (void *) &proc);

        new_msg->data_couple[new_i].data_set->header.length = htons(proc.length);
        new_msg->data_couple[new_i].data_set->header.flowset_id = htons(new_msg->data_couple[new_i].data_template->template_id);

        /*
         * We use a second loop index for cases where a data_couple does not feature a template,
         * so no 'gaps' will be present in the list of data sets.
         */
        ++new_i;
    }

    /* Demarcate end of data records in set */
    new_msg->data_couple[new_i].data_set = NULL;

    /* Don't send empty IPFIX messages (i.e., message includes no templates, option templates, or data records) */
    if (proc.offset == IPFIX_HEADER_LENGTH) {
        MSG_DEBUG(msg_module, "[%u] Empty IPFIX message detected; dropping message", msg->input_info->odid);
        free(proc.key);
        free(proc.msg);
        free(new_msg);
        drop_message(conf->ip_config, message);
        return 0;
    }

    /* Update IPFIX message length (in header) */
    new_msg->pkt_header->length = htons(proc.offset);
    new_msg->input_info = msg->input_info;
    new_msg->templ_records_count = msg->templ_records_count;
    new_msg->opt_templ_records_count = msg->opt_templ_records_count;
    new_msg->data_records_count = msg->data_records_count;
    new_msg->source_status = msg->source_status;
    new_msg->live_profile = msg->live_profile;
    new_msg->plugin_id = msg->plugin_id;
    new_msg->plugin_status = msg->plugin_status;
    new_msg->metadata = msg->metadata;
    msg->metadata = NULL;

    free(proc.key);

    drop_message(conf->ip_config, message);
    pass_message(conf->ip_config, (void *) new_msg);
    return 0;
}

/**
 * \brief Close intermediate Plugin
 *
 * \param[in] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_close(void *config)
{
    struct httpfieldmerge_config *conf;
    conf = (struct httpfieldmerge_config *) config;

    /* Clean up templ_stats hashmap */
    struct templ_stats_elem_t *current_templ_stats, *tmp;
    HASH_ITER(hh, conf->templ_stats, current_templ_stats, tmp) {
        HASH_DEL(conf->templ_stats, current_templ_stats);
        free(current_templ_stats); 
    }

    free(conf);

    return 0;
}
