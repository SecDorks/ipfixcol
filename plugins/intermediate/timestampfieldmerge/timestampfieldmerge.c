/*
 * \file timestampfieldmerge.c
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'httpfieldmerge' intermediate plugin.
 *
 * Intermediate plugin for IPFIXcol that merges timestamp-related fields
 * into timestamp fields that are widely accepted in IPFIX flow data analyis,
 * namely e0id152 (flowStartMilliseconds) and e0id153 (flowEndMilliseconds).
 * The following set of fields are currently supported as conversion source
 * fields:
 *
 *  - e0id21 (flowEndSysUpTime)
 *  - e0id22 (flowStartSysUpTime)
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "timestampfieldmerge.h"

/* API version constant */
IPFIXCOL_API_VERSION;

/**
 * \brief Determines whether template features timestamp-related fields
 * that must be processed
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void templates_stat_processor(uint8_t *rec, int rec_len, void *data)
{
    struct processor *proc = (struct processor *) data;
    struct ipfix_template_record *record = (struct ipfix_template_record *) rec;
    (void) rec_len;
    int i;

    /* Prepare hashmap lookup key */
    struct templ_stats_key_t *templ_stats_key = calloc(1, proc->plugin_conf->templ_stats_key_len);
    if (!templ_stats_key) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return;
    }

    uint16_t template_id = ntohs(record->template_id);

    /* Set key values */
    templ_stats_key->od_id = proc->odid;
    templ_stats_key->ip_id = proc->plugin_conf->ip_id;
    templ_stats_key->template_id = template_id;

    /* Retrieve statistics from hashmap */
    struct templ_stats_elem_t *templ_stats;
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &templ_stats_key->od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    if (templ_stats == NULL) { /* Do only if it was not done (successfully) before */
        templ_stats = calloc(1, sizeof(struct templ_stats_elem_t));
        if (!templ_stats) {
            MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }

        templ_stats->start_time_field_ID = 0;
        templ_stats->end_time_field_ID = 0;
        templ_stats->od_id = proc->odid;
        templ_stats->ip_id = proc->plugin_conf->ip_id;
        templ_stats->template_id = template_id;

        /* Store result in hashmap */
        HASH_ADD(hh, proc->plugin_conf->templ_stats, od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    }

    /* Check for flowStartSysUpTime, e0id22 */
    if (template_record_get_field(record, 0, flowStartSysUpTime, NULL) != NULL) {
        templ_stats->start_time_field_ID = flowStartSysUpTime;
    }

    /* Check for flowEndSysUpTime, e0id21 */
    if (template_record_get_field(record, 0, flowEndSysUpTime, NULL) != NULL) {
        templ_stats->end_time_field_ID = flowEndSysUpTime;
    }
}

/**
 * \brief Processing of template records and option template records
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: processor)
 */
void template_record_processor(uint8_t *rec, int rec_len, void *data)
{

}

/**
 * \brief Processing of data records
 *
 * \param[in] rec Pointer to data record
 * \param[in] rec_len Data record length
 * \param[in] data Any-type data structure (here: processor)
 */
void data_record_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
{

}

/**
 *  \brief Initialize intermediate plugin
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
    struct plugin_config *conf;

    conf = (struct plugin_config *) calloc(1, sizeof(*conf));
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
    conf->templ_stats_key_len = offsetof(struct templ_stats_elem_t, template_id)
            + sizeof(uint16_t) /* Last key component, ip_id, is if type 'uint32_t' */
            - offsetof(struct templ_stats_elem_t, od_id);

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
    struct plugin_config *conf;
    struct processor proc;
    struct ipfix_message *msg, *new_msg;
    struct ipfix_template *templ, *new_templ;
    struct input_info_network *info;
    uint16_t prev_offset;
    uint32_t tsets = 0, otsets = 0;
    uint16_t i, new_i;

    conf = (struct plugin_config *) config;
    msg = (struct ipfix_message *) message;
    info = (struct input_info_network *) msg->input_info;

    MSG_DEBUG(msg_module, "[%u] Received IPFIX message...", msg->input_info->odid);

    /* Check whether source was closed */
    if (msg->source_status == SOURCE_STATUS_CLOSED) {
        // MSG_WARNING(msg_module, "Source closed; skipping IPFIX message...");
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /* Check whether this is an IPFIX message. Note that NetFlow v5/v9 and sFlow
     * packets are converted to IPFIX within the input plugins. Ignore this message
     * in case it is not an IPFIX message (v10).
     */
    if (msg->pkt_header->version != htons(IPFIX_VERSION)) {
        MSG_WARNING(msg_module, "[%u] Unexpected IPFIX version detected (%X); skipping IPFIX message...",
                msg->input_info->odid, msg->pkt_header->version);
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /* Check for invalid message length (may be used as part of an attack). Please note:
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
    proc.allocated_msg_len = new_msg_length;
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
        template_set_process_records(msg->templ_set[i], proc.type, &template_record_processor, (void *) &proc);

        /* Check whether a new template set was added by 'template_record_processor' */
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

        /* Copy full option template set to new message */
        uint16_t set_len = ntohs(msg->opt_templ_set[i]->header.length);
        memcpy(proc.msg + proc.offset, msg->opt_templ_set[i], set_len);
        proc.offset += set_len;
        proc.length = set_len;

        /* Check whether a new options template set was added by 'other_template_rec_processor' */
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

        /* Skip processing in case there is no template available for this data set. This may
         * be caused by a problem in a previous intermediate plugin.
         */
        if (!templ) {
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
        memcpy(proc.msg + proc.offset, &(msg->data_couple[i].data_set->header), sizeof(struct ipfix_set_header));
        proc.offset += sizeof(struct ipfix_set_header);
        proc.length = sizeof(struct ipfix_set_header);

        /* Update 'data_couple' by adjusting pointers to updated data structures */
        new_msg->data_couple[new_i].data_set = ((struct ipfix_data_set *) ((uint8_t *) proc.msg + proc.offset - sizeof(struct ipfix_set_header)));
        new_msg->data_couple[new_i].data_template = new_templ;

        /* Increase number of references to template */
        new_templ->last_message = templ->last_message;
        new_templ->last_transmission = templ->last_transmission;
        tm_template_reference_inc(new_templ);

        /* Process template set records; select processor based on PEN */
        data_set_process_records(msg->data_couple[i].data_set, new_templ, &data_record_processor, (void *) &proc);

        new_msg->data_couple[new_i].data_set->header.length = htons(proc.length);
        new_msg->data_couple[new_i].data_set->header.flowset_id = htons(new_msg->data_couple[new_i].data_template->template_id);

        /* We use a second loop index for cases where a data_couple does not feature a template,
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
    struct plugin_config *conf;
    conf = (struct plugin_config *) config;

    /* Clean up templ_stats hashmap */
    struct templ_stats_elem_t *current_templ_stats, *templ_tmp;
    HASH_ITER(hh, conf->templ_stats, current_templ_stats, templ_tmp) {
        HASH_DEL(conf->templ_stats, current_templ_stats);
        free(current_templ_stats);
    }

    free(conf);
    return 0;
}
