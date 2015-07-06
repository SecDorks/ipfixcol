/*
 * \file ipfixgenerator.c
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'IPFIX generator' input plugin.
 *
 * IPFIXcol input plugin for generating semi-random IPFIX traffic. The main
 * purpose of this plugin is performance testing.
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

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#include "ipfixgenerator.h"

/* API version constant */
IPFIXCOL_API_VERSION;

/* Identifier for MSG_* macros */
static char *msg_module = "ipfixgenerator";

#include "ipfixgenerator_config.h"

/**
 * \brief Retrieve extended specifications (from ipfixgenerator_config.h)
 * for a specified IE
 *
 * \param[in] eid Private enterprise number for IE
 * \param[in] id Field ID
 * \return Field speicification, or NULL upon failure
 */
struct ipfix_ie *get_ie_ext_spec(uint16_t eid, uint16_t id)
{
    struct ipfix_ie *ie = NULL;
    int i;
    for (i = 0; i < all_fields_count; ++i) {
        if (all_fields[i].eid == eid && all_fields[i].id == id) {
            ie = &all_fields[i];
        }
    }

    return ie;
}

/**
 * \brief Generate a random String of the specified length
 *
 * \param[in] s Pointer to the generated String
 * \param[in] len Length of the generated String
 */
void generate_random_str(char *s, const int len)
{
    static const char alphanum[] = "abcdefghijklmnopqrstuvwxyz";

    int i;
    for (i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

/**
 * \brief Provide a pointer to one particular (randomly selected)
 * record in the specified template set
 *
 * \param[in] templ_set Template set to select record from
 * \return Pointer to randomly selected record
 */
struct ipfix_template_record *select_random_templ_record(struct ipfix_template_set *templ_set)
{
    struct ipfix_template_record *templ_rec;
    uint8_t *p = (uint8_t*) &templ_set->first_record;
    uint8_t rec_count = 0;

    /* Count number of records in set */
    while (p < (uint8_t*) templ_set + ntohs(templ_set->header.length)) {
        ++rec_count;

        templ_rec = (struct ipfix_template_record *) p;
        p += tm_template_record_length(templ_rec, ((uint8_t *) templ_set + ntohs(templ_set->header.length)) - p, TM_TEMPLATE, NULL);
    }

    /* Select random record ID */
    uint8_t selected_rec_id = rand() % rec_count;

    /* Obtain pointer to record */
    p = (uint8_t*) &templ_set->first_record;
    while (p < (uint8_t*) templ_set + ntohs(templ_set->header.length)) {
        templ_rec = (struct ipfix_template_record*) p;

        if (selected_rec_id == 0) {
            break;
        }

        p += tm_template_record_length(templ_rec, ((uint8_t *) templ_set + ntohs(templ_set->header.length)) - p, TM_TEMPLATE, NULL);
        --selected_rec_id;
    }

    return templ_rec;
}

/**
 * \brief Converts a uint64_t value to network byte order
 *
 * \param[in] val Integer value to be converted
 * \return Integer in network byte order
 */
uint64_t htonll(uint64_t val)
{
    uint32_t val_1 = htonl(val >> 32);
    uint32_t val_2 = htonl((uint32_t) val);
    return ((uint64_t) val_2 << 32) + val_1;
}

/**
 * \brief Initialize input plugin
 *
 * \param[in] params configuration xml for the plugin
 * \param[out] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int input_init(char *params, void **config)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    struct ipfixgenerator_config *conf = calloc(1, sizeof(*conf));
    if (!conf) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return -1;
    }

    /* Initialize config structure */
    conf->last_templates_transmission = 0;
    conf->templ_sets_count = 0;
    conf->data_records_sent = 0;

    /* Speed control */
    conf->last_data_records_sent = 0;
    conf->last_speed_check = 0;
    conf->sleep_time_usec = 5000;

    /* Initialize input info data structure */
    conf->info = calloc(1, sizeof(struct input_info_file));
    if (!conf->info) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return -1;
    }

    /* Load XML config */
    doc = xmlReadMemory(params, strlen(params), "nobase.xml", NULL, 0);
    if (doc == NULL) {
        MSG_ERROR(msg_module, "Could not parse plugin configuration");
        free(conf);
        return -1;
    }

    /* Set default values */
    conf->info->odid = DEFAULT_ODID;
    conf->max_packets = DEFAULT_MAX_PACKETS;
    conf->max_records = DEFAULT_MAX_RECORDS;
    conf->target_fps = DEFAULT_FPS;

    node = xmlDocGetRootElement(doc);
    if (node == NULL) {
        MSG_NOTICE(msg_module, "Empty plugin configuration detected; falling back to default settings");
    } else {
        if (xmlStrcmp(node->name, (const xmlChar *) "ipfixgenerator") != 0) {
            MSG_ERROR(msg_module, "Bad plugin configuration detected (root node != 'proxy')");
            free(conf);
            return -1;
        }

        node = node->xmlChildrenNode;
        while (node != NULL) {
            /* Skip processing this node in case it's a comment */
            if (node->type == XML_COMMENT_NODE) {
                node = node->next;
                continue;
            }

            if (xmlStrcmp(node->name, (const xmlChar *) "odid") == 0) {
                char *odid_str = (char *) xmlNodeGetContent(node->xmlChildrenNode);

                /* Only consider this node if its value is non-empty */
                if (strlen(odid_str) > 0) {
                    conf->info->odid = atoi(odid_str);
                } else {
                    conf->info->odid = DEFAULT_ODID;
                }

                xmlFree(odid_str);
            } else if (xmlStrcmp(node->name, (const xmlChar *) "fps") == 0) {
                char *fps_str = (char *) xmlNodeGetContent(node->xmlChildrenNode);

                /* Only consider this node if its value is non-empty */
                if (strlen(fps_str) > 0) {
                    conf->target_fps = atoi(fps_str);
                } else {
                    conf->target_fps = DEFAULT_FPS;
                }

                xmlFree(fps_str);
            } else if (xmlStrcmp(node->name, (const xmlChar *) "maxPackets") == 0) {
                char *max_packets_str = (char *) xmlNodeGetContent(node->xmlChildrenNode);

                /* Only consider this node if its value is non-empty */
                if (strlen(max_packets_str) > 0) {
                    conf->max_packets = atoi(max_packets_str);
                } else {
                    conf->max_packets = DEFAULT_MAX_PACKETS;
                }

                xmlFree(max_packets_str);
            } else if (xmlStrcmp(node->name, (const xmlChar *) "maxRecords") == 0) {
                char *max_records_str = (char *) xmlNodeGetContent(node->xmlChildrenNode);

                /* Only consider this node if its value is non-empty */
                if (strlen(max_records_str) > 0) {
                    conf->max_records = atoi(max_records_str);
                } else {
                    conf->max_records = DEFAULT_MAX_RECORDS;
                }

                xmlFree(max_records_str);
            } else {
                MSG_WARNING(msg_module, "Unknown plugin configuration key ('%s')", node->name);
            }

            node = node->next;
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    conf->info->sequence_number = 0;
    conf->info->name = "ipfix-generator";
    conf->info->status = SOURCE_STATUS_NEW;
    conf->info->type = SOURCE_TYPE_IPFIX_FILE;

    *config = conf;

    /* Initialize random number generator seed */
    srand(time(NULL));

    MSG_NOTICE(msg_module, "Plugin initialization completed successfully");
    return 0;
}

/**
 * \brief Pass input data from the input plugin into the IPFIXcol core
 *
 * IP addresses are passed as returned by recvfrom and getsockname,
 * ports are in host byte order
 *
 * \param[in] config plugin_conf structure
 * \param[out] info Information structure describing the source of the data.
 * \param[out] packet Flow information data in the form of IPFIX packet.
 * \param[out] source_status Status of source (new, opened, closed)
 * \return the length of packet on success, INPUT_CLOSE when some connection
 *  closed, INPUT_ERROR on error.
 */
int get_packet(void *config, struct input_info** info, char **packet, int *source_status)
{
    struct ipfixgenerator_config *conf;
    int i, j;
    uint8_t *msg;
    uint16_t len;

    conf = (struct ipfixgenerator_config *) config;
    time_t now = time(NULL);

    /* Check whether generation must be stopped */
    if ((conf->max_packets > 0 && conf->packets_sent >= conf->max_packets)
            || (conf->max_records > 0 && conf->data_records_sent >= conf->max_records)) {
        conf->info->status = SOURCE_STATUS_CLOSED;

        *info = (struct input_info*) conf->info;
        *packet = NULL;
        *source_status = conf->info->status;

        return INPUT_CLOSED;
    }

    /* Perform speed check */
    if (conf->last_speed_check == 0) {
        conf->last_speed_check = now;
        conf->last_data_records_sent = conf->data_records_sent;
    } else if (now > conf->last_speed_check) {
        if (conf->data_records_sent - conf->last_data_records_sent > conf->target_fps) {
            // MSG_DEBUG(msg_module, " >> Going slower... (fps: %u, sleep time: %u)", conf->data_records_sent - conf->last_data_records_sent, conf->sleep_time_usec);
            conf->sleep_time_usec += 100;
        } else {
            // MSG_DEBUG(msg_module, " >> Going faster... (fps: %u, sleep time: %u)", conf->data_records_sent - conf->last_data_records_sent, conf->sleep_time_usec);
            conf->sleep_time_usec -= 100;
        }

        conf->last_speed_check = now;
        conf->last_data_records_sent = conf->data_records_sent;
    }

    /* Check whether sleeping time has meaningful values */
    if (conf->sleep_time_usec > 1000000) {
        MSG_WARNING(msg_module, "Plugin sleep time is more than 1 second");
    } else if (conf->sleep_time_usec <= 0) {
        MSG_WARNING(msg_module, "Plugin sleep time has invalid value (%u)", conf->sleep_time_usec);
    }

    if (conf->sleep_time_usec > 0) {
        usleep(conf->sleep_time_usec);
    }

    msg = calloc(1, IPFIX_MSG_MAX_LENGTH);
    if (!msg) {
        MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
        return INPUT_ERROR;
    }

    /* Generate header */
    struct ipfix_header *header = (struct ipfix_header *) msg;
    header->version = htons(0x000a);
    header->export_time = htonl(now);
    header->sequence_number = htonl(conf->data_records_sent);
    header->observation_domain_id = htonl(DEFAULT_ODID);

    len = IPFIX_HEADER_LENGTH;

    /*
     * Generate templates if...
     *      (1) No template have been generated before
     *      (2) Periodic template reporting is necessary (by time)
     *      (3) Periodic template reporting is necessary (by number of packets)
     */
    if (conf->last_templates_transmission == 0
            || now - conf->last_templates_transmission > TEMPL_RESEND_SEC
            || conf->packets_sent % TEMPL_RESEND_PKTS == 0) {
        /* Check whether we resend the current templates or whether we generate new ones */
        if (conf->templ_sets_count > 0 && rand() % 2 == 0) {
            MSG_DEBUG(msg_module, "Resending current template sets");
        } else {
            MSG_DEBUG(msg_module, "Generating new template sets");

            /* Clean up existing template sets */
            for (i = 0; i < MSG_MAX_TEMPL_SETS && i < conf->templ_sets_count; ++i) {
                free(conf->templ_set[i]);
            }
            conf->templ_sets_count = 0;

            /* Determine the number of template records to be generated (with a minimum of one) */
            uint8_t templ_recs_generate_count = rand() % MAX_TEMPLATE_RECORDS;
            templ_recs_generate_count = MAX(1, templ_recs_generate_count);

            /* Generate new template set + records */
            /*
             * FIXME We currently allocate enough memory for being able to
             * allocate the maximum number of IEs for this template. In case
             * we know in advance how many IEs this template will feature,
             * the memory allocation can be a bit more precise.
             */
            uint16_t templ_set_len = sizeof(struct ipfix_template_set)
                    + templ_recs_generate_count * (IPFIX_RECORD_HEADER_LENGTH + all_fields_count * sizeof(template_ie));
            struct ipfix_template_set *templ_set = calloc(1, templ_set_len);
            if (!templ_set) {
                MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                return -1;
            }

            templ_set->header.flowset_id = htons(IPFIX_TEMPLATE_FLOWSET_ID);
            templ_set->header.length = IPFIX_SET_HEADER_LENGTH;
            conf->templ_set[conf->templ_sets_count] = templ_set;

            for (i = 0; i < templ_recs_generate_count; ++i) {
                struct ipfix_template_record *templ_rec = (struct ipfix_template_record *) (((uint8_t *) templ_set) + templ_set->header.length);
                templ_rec->template_id = htons(IPFIX_MIN_RECORD_FLOWSET_ID + i);
                templ_set->header.length += IPFIX_RECORD_HEADER_LENGTH;

                uint16_t field_index = 0;
                for (j = 0; j < all_fields_count; ++j) {
                    /* Perform random field selection */
                    if (all_fields[j].mandatory || rand() % 2 == 0) {
                        template_ie ie;

                        /* Add enterprise number, if necessary */
                        if (all_fields[j].eid == 0) {
                            ie.ie.id = htons(all_fields[j].id);
                            ie.ie.length = htons(all_fields[j].length);

                            /* Add IE data structure to template record */
                            templ_rec->fields[field_index] = ie;

                            /* Update set length in template set header */
                            templ_set->header.length += IPFIX_FIELD_SPECIFIER_LENGTH;
                        } else {
                            ie.ie.id = htons(all_fields[j].id | 0x8000);
                            ie.ie.length = htons(all_fields[j].length);

                            /* Add IE data structure to template record */
                            templ_rec->fields[field_index] = ie;
                            ++field_index;

                            /* Add enterprise number to template record */
                            ie.enterprise_number = htonl(all_fields[j].eid);
                            templ_rec->fields[field_index] = ie;

                            /* Update set length in template set header */
                            templ_set->header.length += IPFIX_FIELD_SPECIFIER_LENGTH + 4;
                        }

                        ++field_index;
                        ++templ_rec->count;
                    }
                }

                /* This must come after set length update because of host byte order vs. network byte order */
                templ_rec->count = htons(templ_rec->count);

                /* Save reference to first record */
                if (i == 0) {
                    templ_set->first_record = *templ_rec;
                }
            }

            templ_set->header.length = htons(templ_set->header.length);
            ++conf->templ_sets_count;
        }

        conf->last_templates_transmission = now;

        /* Copy template sets to IPFIX message */
        uint16_t set_len;
        for (i = 0; i < MSG_MAX_TEMPL_SETS && i < conf->templ_sets_count; ++i) {
            set_len = ntohs(conf->templ_set[i]->header.length);
            memcpy(msg + len, conf->templ_set[i], set_len);
            len += set_len;

            /* Since template sets/record are 4-byte aligned by definition, there is no need to add padding here */
        }
    } else {
        /* No need to (re)send templates; generate and send datasets instead */
        MSG_DEBUG(msg_module, "Generating data records");

        for (i = 0; i < MSG_MAX_TEMPL_SETS && i < conf->templ_sets_count; ++i) {
            struct ipfix_template_set *templ_set = conf->templ_set[i];

            /* Determine the number of data records to be generated (with a minimum of one) */
            uint8_t data_record_generate_count = rand() % MAX_DATA_RECORDS;
            data_record_generate_count = MAX(1, data_record_generate_count);

            /* Select random template record to generate data records for */
            struct ipfix_template_record *templ_rec = select_random_templ_record(templ_set);

            /* Generate data set header */
            struct ipfix_set_header *data_set_header = calloc(1, sizeof(struct ipfix_set_header));
            if (!data_set_header) {
                MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                return -1;
            }

            data_set_header->flowset_id = templ_rec->template_id;
            data_set_header->length = IPFIX_SET_HEADER_LENGTH;
            uint8_t *data_set_header_len_p = msg + len + 2; /* + 2 is because length field is at offset '2' */

            /* 
             * Copy data set header to IPFIX message
             * Note: 'length' field will be updated later
             */
            memcpy(msg + len, data_set_header, IPFIX_SET_HEADER_LENGTH);
            len += IPFIX_SET_HEADER_LENGTH;

            while (data_record_generate_count > 0) {
                /* Update statistics for sequence number generation */
                ++conf->data_records_sent;

                uint16_t templ_rec_field_count = ntohs(templ_rec->count);
                uint16_t field_index = 0;
                while (field_index < templ_rec_field_count) {
                    uint32_t field_pen = 0;
                    uint16_t field_id = ntohs(templ_rec->fields[field_index].ie.id);
                    if (field_id & 0x8000) {
                        field_id &= ~0x8000; /* Unset enterprise bit */

                        ++field_index;
                        field_pen = ntohl(templ_rec->fields[field_index].enterprise_number);
                    }

                    struct ipfix_ie *ie = get_ie_ext_spec(field_pen, field_id);
                    if (!ie) {
                        MSG_ERROR(msg_module, "Could not find IE specification (PEN: %u, ID: %u)", field_pen, field_id);
                        break;
                    }

                    switch (ie->type) {
                        case IPFIX_TYPE_UNSIGNED8: ;
                                uint8_t val8 = rand() % 256;
                                memcpy(msg + len, &val8, ie->length);
                                break;
                        case IPFIX_TYPE_UNSIGNED16: ;
                                uint16_t val16 = rand() % 65536;
                                val16 = htons(val16);
                                memcpy(msg + len, &val16, ie->length);
                                break;
                        case IPFIX_TYPE_UNSIGNED32: ;
                                uint32_t val32 = rand() % 65536;
                                val32 = htonl(val32);
                                memcpy(msg + len, &val32, ie->length);
                                break;
                        case IPFIX_TYPE_UNSIGNED64: ;
                                uint64_t val64 = rand() % 65536;
                                val64 = htonll(val64);
                                memcpy(msg + len, &val64, ie->length);
                                break;
                        case IPFIX_TYPE_IPV4ADDRESS: ;
                                uint32_t valipv4 = rand() % 4294967296;
                                valipv4 = htonl(valipv4);
                                memcpy(msg + len, &valipv4, ie->length);
                                break;
                        case IPFIX_TYPE_IPV6ADDRESS: ;
                                uint64_t valipv6 = rand() % 4294967296;
                                valipv6 = htonll(valipv6);
                                memcpy(msg + len, &valipv4, ie->length);
                                break;
                        case IPFIX_TYPE_STRING: ;
                                char *s = calloc(ie->length + 1, sizeof(char));
                                if (!s) {
                                    MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
                                    return -1;
                                }

                                generate_random_str(s, ie->length);
                                s[ie->length] = '\0';
                                memcpy(msg + len, s, ie->length);
                                free(s);
                                break;
                        case IPFIX_TYPE_TIME_MILLISEC: ; /* unsigned64 */
                                uint64_t time_msec = now * 1000; /* now (time(NULL)) returns UNIX time in seconds */
                                time_msec = htonll(time_msec);
                                memcpy(msg + len, &time_msec, ie->length);
                                break;
                        default:
                                MSG_ERROR(msg_module, "Invalid field type detected (%u)", ie->type);
                                uint8_t val = 0;
                                memcpy(msg + len, &val, ie->length);
                                break;
                    }

                    /* Update data set length */
                    data_set_header->length += ie->length;

                    /* Update IPFIX message length */
                    len += ie->length;

                    ++field_index;
                }

                --data_record_generate_count;
            }

            /* Add padding bytes, if necessary */
            if (data_set_header->length % 4 != 0) {
                int padding_len = 4 - (data_set_header->length % 4);
                memset(msg + len, 0, padding_len);
                data_set_header->length += padding_len;
                len += padding_len;
            }

            /* Update length in data set header */
            data_set_header->length = htons(data_set_header->length);
            memcpy(data_set_header_len_p, &data_set_header->length, 2); /* Length field is 2 bytes in size */
            free(data_set_header);
        }
    }

    /* Update length in IPFIX message header */
    header->length = htons(len);

    /* Convert IPFIX message data structure to packet */
    *packet = (void *) msg;

    MSG_DEBUG(msg_module, "Generated IPFIX message (seq. no: %u, len: %u)", ntohl(header->sequence_number), ntohs(header->length));

    /* Set appropriate source status */
    if (conf->info->status == SOURCE_STATUS_NEW) {
        conf->info->status = SOURCE_STATUS_OPENED;
    }

    *source_status = conf->info->status;
    *info = (struct input_info*) conf->info;

    conf->packets_sent++;

    return len;
}

/**
 * \brief Close input plugin
 *
 * \param[in] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int input_close(void **config)
{
    struct ipfixgenerator_config *conf;

    conf = (struct ipfixgenerator_config *) *config;

    /* Clean up template sets */
    int i;
    for (i = 0; i < MSG_MAX_TEMPL_SETS && i < conf->templ_sets_count; ++i) {
        free(conf->templ_set[i]);
    }
    conf->templ_sets_count = 0;

    free(conf->info);
    free(*config);

    return 0;
}
