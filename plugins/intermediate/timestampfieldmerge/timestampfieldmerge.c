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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "timestampfieldmerge.h"

/* API version constant */
IPFIXCOL_API_VERSION;

// void print_mem_addr(uint8_t *p, uint16_t len)
// {
//     char *addr;
//     int i;
//     for (i = 0; i < len; ++i) {
//         addr = (char *) (p + i);
//         MSG_DEBUG(msg_module, " - %p: %.2x", addr, *addr);
//     }
// }

/**
 * \brief Determines whether template features timestamp-related fields
 * that must be processed
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: httpfieldmerge_processor)
 */
void template_rec_stat_processor(uint8_t *rec, int rec_len, void *data)
{
    struct processor *proc = (struct processor *) data;
    struct ipfix_template_record *record = (struct ipfix_template_record *) rec;
    (void) rec_len;

    /* Prepare hashmap lookup key */
    uint16_t template_id = ntohs(record->template_id);
    proc->templ_stats_key->od_id = proc->odid;
    proc->templ_stats_key->ip_id = proc->plugin_conf->ip_id;
    proc->templ_stats_key->template_id = template_id;

    /* Retrieve statistics from hashmap */
    struct templ_stats_elem_t *templ_stats;
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &proc->templ_stats_key->od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    if (templ_stats == NULL) { /* Do only if it was not done (successfully) before */
        templ_stats = calloc(1, sizeof(struct templ_stats_elem_t));
        if (!templ_stats) {
            MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
            return;
        }

        templ_stats->start_time_field_id = 0;
        templ_stats->end_time_field_id = 0;
        templ_stats->sysuptime_field_id = 0;
        templ_stats->od_id = proc->odid;
        templ_stats->ip_id = proc->plugin_conf->ip_id;
        templ_stats->template_id = template_id;

        /* Store result in hashmap */
        HASH_ADD(hh, proc->plugin_conf->templ_stats, od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    }

    struct ipfix_entity field;

    /* Check for flowStartMilliseconds, e0id152 */
    field = (struct ipfix_entity) flowStartMilliseconds;
    if (template_record_get_field(record, field.pen, field.element_id, NULL) != NULL) {
        templ_stats->start_time_field_id = field.element_id;
    }

    /* Check for flowEndMilliseconds, e0id153 */
    field = (struct ipfix_entity) flowEndMilliseconds;
    if (template_record_get_field(record, field.pen, field.element_id, NULL) != NULL) {
        templ_stats->end_time_field_id = field.element_id;
    }

    /* Stop further processing if target fields are already found in template record */
    if (templ_stats->start_time_field_id != 0 && templ_stats->end_time_field_id != 0) {
        return;
    }

    /* Check for flowStartSysUpTime, e0id22 */
    field = (struct ipfix_entity) flowStartSysUpTime;
    if (template_record_get_field(record, field.pen, field.element_id, NULL) != NULL) {
        templ_stats->start_time_field_id = field.element_id;
    }

    /* Check for flowEndSysUpTime, e0id21 */
    field = (struct ipfix_entity) flowEndSysUpTime;
    if (template_record_get_field(record, field.pen, field.element_id, NULL) != NULL) {
        templ_stats->end_time_field_id = field.element_id;
    }

    /* Check for systemInitTimeMilliseconds, e0id160 */
    field = (struct ipfix_entity) systemInitTimeMilliseconds;
    if (template_record_get_field(record, field.pen, field.element_id, NULL) != NULL) {
        templ_stats->end_time_field_id = field.element_id;
    }
}

/**
 * \brief Processing of template records and option template records
 *
 * \param[in] rec Pointer to template record
 * \param[in] rec_len Template record length
 * \param[in] data Any-type data structure (here: processor)
 */
void template_rec_processor(uint8_t *rec, int rec_len, void *data)
{
    struct processor *proc = (struct processor *) data;
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

    uint16_t template_id = ntohs(old_rec->template_id);
    MSG_DEBUG(msg_module, "> [template_rec_processor] Old template ID: %u", template_id);

    /* Set key values */
    proc->templ_stats_key->od_id = proc->odid;
    proc->templ_stats_key->ip_id = proc->plugin_conf->ip_id;
    proc->templ_stats_key->template_id = template_id;

    /* Retrieve statistics from hashmap */
    struct templ_stats_elem_t *templ_stats;
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &proc->templ_stats_key->od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    if (templ_stats == NULL) {
        MSG_ERROR(msg_module, "Could not find key '%u' in hashmap; using original template", template_id);

        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /* Skip further processing if template does not feature any of the timestamp fields
     * that require processing */
    if (templ_stats->start_time_field_id != proc->plugin_conf->field_flowStartSysUpTime.element_id
            && templ_stats->end_time_field_id != proc->plugin_conf->field_flowEndSysUpTime.element_id) {
        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /* Copy original template record; BYTES_4 is because target timestamps are
     * 8 bytes in size instead of 4 bytes */
    new_rec = calloc(1, rec_len + (2 * BYTES_4));
    if (!new_rec) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return;
    }

    memcpy(new_rec, old_rec, rec_len);

    /* Find timestamp fields and replace them; iterate over all fields in template record */
    uint16_t count = 0, index = 0;
    uint16_t field_id;
    while (count < ntohs(new_rec->count)
            && (uint8_t *) &new_rec->fields[index] - (uint8_t *) new_rec < rec_len) {
        field_id = ntohs(new_rec->fields[index].ie.id);
        if (field_id == proc->plugin_conf->field_flowStartSysUpTime.element_id) {
            new_rec->fields[index].ie.id = htons((struct ipfix_entity) flowStartMilliseconds.element_id);
            new_rec->fields[index].ie.length = htons(BYTES_8);
        } else if (field_id == proc->plugin_conf->field_flowEndSysUpTime.element_id) {
            new_rec->fields[index].ie.id = htons((struct ipfix_entity) flowEndMilliseconds.element_id);
            new_rec->fields[index].ie.length = htons(BYTES_8);
        }

        /* PEN comes just after the IE, before the next IE; skip it */
        if (field_id & 0x8000) {
            ++index;
        }

        ++count;
        ++index;
    }

    /* Store it in template manager */
    proc->key->tid = template_id;
    MSG_DEBUG(msg_module, "> [template_rec_processor] New template ID: %u", template_id);

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
 * \param[in] data Any-type data structure (here: processor)
 */
void data_rec_processor(uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data)
{
    struct processor *proc = (struct processor *) data;
    (void) templ;

    /* Check whether we will exceed the allocated memory boundary */
    if (proc->offset + rec_len > proc->allocated_msg_len) {
        MSG_ERROR(msg_module, "Not enough memory allocated for processing full message (allocated: %u, current offset: %u)",
                proc->allocated_msg_len, proc->offset);
        return;
    }

    /* Get structure from hashmap that provides information about current template */
    uint16_t template_id = templ->template_id;

    /* Set key values */
    proc->templ_stats_key->od_id = proc->odid;
    proc->templ_stats_key->ip_id = proc->plugin_conf->ip_id;
    proc->templ_stats_key->template_id = template_id;

    /* Retrieve statistics from hashmap */
    struct templ_stats_elem_t *templ_stats;
    HASH_FIND(hh, proc->plugin_conf->templ_stats, &proc->templ_stats_key->od_id, proc->plugin_conf->templ_stats_key_len, templ_stats);
    if (templ_stats == NULL) {
        MSG_ERROR(msg_module, "Could not find key '%u' in hashmap; using original template", template_id);

        /* Copy existing record to new message */
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    /* Skip further processing if template does not feature any of the timestamp fields
     * that require processing */
    if (templ_stats->start_time_field_id != proc->plugin_conf->field_flowStartSysUpTime.element_id
            && templ_stats->end_time_field_id != proc->plugin_conf->field_flowEndSysUpTime.element_id) {
        /* Copy original data record */
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    MSG_DEBUG(msg_module, "----- Data record (ptr: %p) -----", rec);
    MSG_DEBUG(msg_module, "Old rec_len: %u", rec_len);

    uint8_t len_spec_bytes; /* Number of bytes used to indicate length of variable-length fields */
    uint16_t count, field_id, field_len, index, offset = 0, prev_offset;
    for (count = index = 0; count < proc->orig_templ->field_count; ++count, ++index) {
        field_id = proc->orig_templ->fields[index].ie.id;
        field_len = proc->orig_templ->fields[index].ie.length;
        len_spec_bytes = 0;

        /* Current field is enterprise-specific */
        if (field_id >> 15) {
            /* Enterprise number */
            field_id &= 0x7FFF;
            ++index;
        }

        prev_offset = offset;

        switch (field_len) {
            case (1):
            case (2):
            case (4):
            case (8):
                offset += field_len;
                break;
            default:
                if (field_len == VAR_IE_LENGTH) {
                    field_len = *((uint8_t *) (rec + offset));
                    len_spec_bytes += 1;
                    offset += 1;

                    if (field_len == 255) {
                        field_len = ntohs(*((uint16_t *) (rec + offset)));
                        len_spec_bytes += 2;
                        offset += 2;
                    }

                    offset += field_len;
                } else {
                    offset += field_len;
                }

                break;
        }

        /* Calculate absolute flow record start and end times based on sysUpTime or collector
         * system time, depending on availability of systemInitTimeMilliseconds field
         */
        int sysUpTime_field_offset, sysUpTime_field_len;
        uint64_t *sysUpTime;
        uint64_t abs_time;
        if (field_id == proc->plugin_conf->field_flowStartSysUpTime.element_id
                || field_id == proc->plugin_conf->field_flowEndSysUpTime.element_id) {
            /* Retrieve sysUpTime; either from data field or approximated by collector system time */
            if (templ_stats->sysuptime_field_id == proc->plugin_conf->field_systemInitTimeMilliseconds.element_id) {
                sysUpTime_field_offset = data_record_field_offset(rec, proc->orig_templ,
                        proc->plugin_conf->field_systemInitTimeMilliseconds.pen,
                        proc->plugin_conf->field_systemInitTimeMilliseconds.element_id,
                        &sysUpTime_field_len);
                message_get_data((uint8_t **) &sysUpTime, rec + sysUpTime_field_offset, sysUpTime_field_len);

                /* Calculate absolute flow record start/end time */
                abs_time = *sysUpTime + ntohl(*((uint32_t *) (rec + offset)));

                free(sysUpTime);
            } else {
                /* proc->time is seconds since UNIX epoch, so converted to milliseconds */
                abs_time = proc->time; // * 1000; FIXME
            }

            /* Store absolute flow record start/end time in record, in place of flowStartSysUpTime/flowEndSysUpTime */
            MSG_DEBUG(msg_module, "    > Setting absolute start time: %u (proc->time: %u)", abs_time, proc->time);
            message_set_data(proc->msg + proc->offset, (uint8_t *) &abs_time,
                    proc->plugin_conf->field_flowStartMilliseconds.length);

            proc->offset += proc->plugin_conf->field_flowStartMilliseconds.length;
            proc->length += proc->plugin_conf->field_flowStartMilliseconds.length;

            /* Add difference between 'new' and 'old' field lengths, in bytes */
            MSG_DEBUG(msg_module, "    > Increasing rec_len by %u bytes", proc->plugin_conf->field_flowStartMilliseconds.length - field_len);
            rec_len += proc->plugin_conf->field_flowStartMilliseconds.length - field_len;
        } else {
            memcpy(proc->msg + proc->offset, rec + prev_offset, field_len + (offset - prev_offset));
            proc->offset += field_len;
            proc->length += field_len;
        }
    }

    MSG_DEBUG(msg_module, "New rec_len: %u", rec_len);
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

    /* Initialize field instances */
    conf->field_flowStartSysUpTime = (struct ipfix_entity) flowStartSysUpTime;
    conf->field_flowEndSysUpTime = (struct ipfix_entity) flowEndSysUpTime;
    conf->field_flowStartMilliseconds = (struct ipfix_entity) flowStartMilliseconds;
    conf->field_flowEndMilliseconds = (struct ipfix_entity) flowEndMilliseconds;
    conf->field_systemInitTimeMilliseconds = (struct ipfix_entity) systemInitTimeMilliseconds;

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

    /* As an estimate for the new message size, we take the old message size and
     * allocate an additional 4 bytes for every record, assuming that we have to
     * 'upgrade' sysUpTimes (4 bytes) to flow*Milliseconds (8 bytes)
     */
    uint16_t new_msg_length = old_msg_length + (msg->data_records_count * BYTES_4);

    /* Allocate memory for new message */
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
    proc.time = time(NULL);

    proc.templ_stats_key = calloc(1, proc.plugin_conf->templ_stats_key_len);
    if (!proc.templ_stats_key) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        free(proc.msg);
        free(new_msg);
        return 1;
    }

    /* Process template sets */
    MSG_DEBUG(msg_module, "[%u] Processing template sets...", msg->input_info->odid);
    proc.type = TM_TEMPLATE;
    for (i = 0; i < MSG_MAX_TEMPL_SETS && msg->templ_set[i]; ++i) {
        prev_offset = proc.offset;

        /* Determine IP versions used within each template set and store result in hashmap. Also,
         * determine exporter PEN based on presence of certain enterprise-specific IEs.
         */
        template_set_process_records(msg->templ_set[i], proc.type, &template_rec_stat_processor, (void *) &proc);

        /* Add template set header, and update offset and length */
        memcpy(proc.msg + proc.offset, &(msg->templ_set[i]->header), 4);
        proc.offset += 4;
        proc.length = 4;

        /* Process all template set records */
        template_set_process_records(msg->templ_set[i], proc.type, &template_rec_processor, (void *) &proc);

        /* Check whether a new template set was added by 'template_rec_processor' */
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

        /* Check whether a new options template set was added by 'template_rec_processor' */
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

        /* Save reference to original template. This is necessary for decoding data records
         * when the accompanying template record has already been modified.
         */
        proc.orig_templ = templ;

        /* Retrieve update template based on (new) template ID */
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
        /* Note: we have to use the old/original template here, since data records
         * are at this stage still using the old structure
         */
        data_set_process_records(msg->data_couple[i].data_set, templ, &data_rec_processor, (void *) &proc);

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
    free(proc.templ_stats_key);

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
