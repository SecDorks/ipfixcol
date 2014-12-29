/*
 * \file proxy.c
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'proxy' intermediate plugin.
 *
 * Intermediate plugin for IPFIXcol that 'translates' flows related to Web proxies,
 * useful for monitoring applications that need to be aware of the real hosts 'behind'
 * the proxy. If this plugin is not used, all HTTP(S) flows will have the Web proxy as
 * their source or destination. Specifically, this plugin performs the following tasks:
 * 
 *     - Add 'original' fields to both template and data records.
 *     - In case the Web proxy is the source of a flow, both the source IPv4/IPv6
 *         address and port number are copied to the 'original' fields. In case the
 *         Web proxy is the destination of a flow, both the destination IPv4/IPv6
 *         address and port number are copied to the 'original' fields.
 *     - The HTTP host and/or URL are used to resolve the IP address of the 'real'
 *         host 'behind' the proxy. Only the first result of the domain name resolution
 *         is used.
 *     - The IP address obtained by domain name resolution and port are placed in the
 *         IPv4/IPv6 address and port number fields, respectively.
 *
 * The enterprise-specific IEs are added to template/data records in the following order
 * (per IP version):
 *
 *      <src_port, src_IP_addr, dst_port, dst_IP_addr>
 *
 * In case a template/data record features both IPv4 and IPv6 IEs, the port number IEs
 * are added only once (together with the IPv4 IEs), to avoid template/data records that
 * feature multiple instances of the same IE.
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

#include "proxy.h"

// Identifier for MSG_* macros
static char *msg_module = "proxy";

// Checks whether a specified element (ID) represents a port number.
static int is_port_number_field (uint16_t id) {
    unsigned int i;
    for (i = 0; i < port_number_fields_count; ++i) {
        if (id == port_number_fields[i].element_id) {
            return 1;
        }
    }

    return 0;
}

/*
 * Checks whether a specified element (ID) belongs to a 'source field' (e.g.,
 * sourceIPv4Address, origSourceTransportPort).
 */
static int is_source_field (uint16_t id) {
    unsigned int i;
    for (i = 0; i < source_fields_count; ++i) {
        if (id == source_fields[i].element_id) {
            return 1;
        }
    }

    return 0;
}

// Returns the enterprise-specific IEs for a specified PEN.
static struct ipfix_entity* pen_to_enterprise_fields (uint16_t pen) {
    struct ipfix_entity *fields;
    switch (pen) {
        case 35632:     fields = (struct ipfix_entity *) ntop_fields;
                        break;

        case 39499:     fields = (struct ipfix_entity *) invea_fields;
                        break;

        default:        MSG_WARNING(msg_module, "Could not retrieve enterprise-specific IEs; unknown PEN (%u)", pen);
    }

    return fields;
}

// This callback function is called once a domain name resolution has completed
static void ares_cb (void *arg, int status, int timeouts, struct hostent *host) {
    struct proxy_ares_processor *ares_proc = (struct proxy_ares_processor *) arg;
    char *ip_addr;
    uint8_t offset;
    unsigned int element_id, template_id, length, i;

    // Determine IP versions used within this template
    template_id = ares_proc->templ->template_id;
    struct templ_stats_elem_t *templ_stats;
    HASH_FIND_INT(ares_proc->proc->plugin_conf->templ_stats, &template_id, templ_stats);
    if (!templ_stats) { // Do only if it was not done (successfully) before
        MSG_ERROR(msg_module, "Could not find template information (template ID: %u)", template_id);
        free(ares_proc->http_hostname);
        free(ares_proc);
        return;
    }

    if (host == NULL || status != ARES_SUCCESS) {
        MSG_WARNING(msg_module, "Failed domain name resolution for '%s': %s", ares_proc->http_hostname, ares_strerror(status));

        // Copy original data record
        memcpy(ares_proc->proc->msg + ares_proc->proc->offset, ares_proc->orig_rec, ares_proc->orig_rec_len);
        ares_proc->proc->offset += ares_proc->orig_rec_len;
        ares_proc->proc->length += ares_proc->orig_rec_len;

        // Add empty 'orig' fields. Field order: <src_port, src_IP_addr, dst_port, dst_IP_addr>
        if (templ_stats->ipv4) {
            for (i = 0; i < orig_fields_count; ++i) {
                memset(ares_proc->proc->msg + ares_proc->proc->offset, 0, orig_fields_IPv4[i].length);
                ares_proc->proc->offset += orig_fields_IPv4[i].length;
                ares_proc->proc->length += orig_fields_IPv4[i].length;
            }
        }
        if (templ_stats->ipv6) {
            for (i = 0; i < orig_fields_count; ++i) {
                /*
                 * Records can feature one instance of an IE at most. Therefore, if this record
                 * features IPv4 data as well, we assume that the port number fields have already
                 * been included. As such, we can skip adding them here again for IPv6.
                 */
                if (templ_stats->ipv4 && is_port_number_field(orig_fields_IPv6[i].element_id)) {
                    continue;
                }

                memset(ares_proc->proc->msg + ares_proc->proc->offset, 0, orig_fields_IPv6[i].length);
                ares_proc->proc->offset += orig_fields_IPv6[i].length;
                ares_proc->proc->length += orig_fields_IPv6[i].length;
            }
        }

        free(ares_proc->http_hostname);
        free(ares_proc);
        return;
    }

    // Only select first IP address (in network byte order)
    ip_addr = host->h_addr_list[0];

    // Convert port number to network byte order
    ares_proc->port_number = htons(ares_proc->port_number);

    // Store pointer to start of data record, which is useful for calculating relative positions of fields later
    uint32_t data_record_offset = ares_proc->proc->offset;

    // Copy original data record
    memcpy(ares_proc->proc->msg + ares_proc->proc->offset, ares_proc->orig_rec, ares_proc->orig_rec_len);
    ares_proc->proc->offset += ares_proc->orig_rec_len;
    ares_proc->proc->length += ares_proc->orig_rec_len;

    /*
     * Obtain pointers to data sources and destinations, and copy data from regular IPv4 address
     * and port number fields to their respective 'original' fields. Field order (per IP version):
     * <src_port, src_IP_addr, dst_port, dst_IP_addr>
     */
    for (i = 0; i < mapping_count; ++i) {
        if (templ_stats->ipv4) {
            element_id = IPv4_field_mappings[i].from.element_id;
            offset = template_contains_field(ares_proc->templ, element_id);
            length = IPv4_field_mappings[i].from.length;
        } else {
            element_id = IPv6_field_mappings[i].from.element_id;
            offset = template_contains_field(ares_proc->templ, element_id);
            length = IPv6_field_mappings[i].from.length;
        }

        memcpy(ares_proc->proc->msg + ares_proc->proc->offset, ares_proc->orig_rec + offset, length);
        ares_proc->proc->offset += length;
        ares_proc->proc->length += length;
    }

    // Copy new data to the regular IP address and port number fields
    for (i = 0; i < mapping_count; ++i) {
        if (templ_stats->ipv4) {
            element_id = IPv4_field_mappings[i].from.element_id;
            length = IPv4_field_mappings[i].from.length;
        } else {
            element_id = IPv6_field_mappings[i].from.element_id;
            length = IPv6_field_mappings[i].from.length;
        }

        /*
         * Check whether the 'current' field is a 'source' field and whether the new information has
         * to be stored in 'source' fields, or whether the 'current' field is a 'destination' field
         * and the new information has to be stored in 'destination' fields.
         */
        if ((ares_proc->proxy_port_field_id == ((struct ipfix_entity) sourceTransportPort).element_id && is_source_field(element_id))
                || (ares_proc->proxy_port_field_id == ((struct ipfix_entity) destinationTransportPort).element_id && !is_source_field(element_id))) {
            offset = template_contains_field(ares_proc->templ, element_id);
        } else {
            continue;
        }

        if (is_port_number_field(element_id)) {
            memcpy(ares_proc->proc->msg + data_record_offset + offset, &ares_proc->port_number, length);
        } else { // IP address
            memcpy(ares_proc->proc->msg + data_record_offset + offset, ip_addr, length);
        }
    }

    free(ares_proc->http_hostname);
    free(ares_proc);
}

// Waits for all domain name resolutions to be ready
static void ares_wait (ares_channel channel) {
    for (;;) {
        struct timeval *tvp, tv;
        fd_set read_fds, write_fds;
        int nfds;
 
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);

        if (nfds == 0){
            break;
        }

        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        ares_process(channel, &read_fds, &write_fds);
    }
}

/*
 * Determines whether template contains IPv4 and/or IPv6 fields. In addition,
 * it is determined whether enterprise-specific IEs are used.
 */ 
void templates_stat_processor (uint8_t *rec, int rec_len, void *data) {
    struct proxy_processor *proc = (struct proxy_processor *) data;
    struct ipfix_template_record *record = (struct ipfix_template_record *) rec;

    // Determine IP versions used within this template
    struct templ_stats_elem_t *templ_stats;
    int template_id = (int) ntohs(record->template_id);
    HASH_FIND_INT(proc->plugin_conf->templ_stats, &template_id, templ_stats);
    if (!templ_stats) { // Do only if it was not done (successfully) before
        templ_stats = malloc(sizeof(struct templ_stats_elem_t));
        templ_stats->id = template_id;
        templ_stats->http_fields_pen = 0;
        templ_stats->ipv4 = (template_record_get_field(record, templ_stats->http_fields_pen, ((struct ipfix_entity) sourceIPv4Address).element_id, NULL) != NULL);
        templ_stats->ipv6 = (template_record_get_field(record, templ_stats->http_fields_pen, ((struct ipfix_entity) sourceIPv6Address).element_id, NULL) != NULL);

        // Store result in hashmap
        HASH_ADD_INT(proc->plugin_conf->templ_stats, id, templ_stats);
    }

    // Determine exporter PEN based on presence of certain enterprise-specific IEs
    if (templ_stats->http_fields_pen == 0) { // Do only if it was not done (successfully) before
        int i;
        // Check enterprise-specific IEs from INVEA-TECH
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, invea_fields[i].pen, ((struct ipfix_entity) invea_fields[i]).element_id, NULL) != NULL) {
                MSG_NOTICE(msg_module, "Detected enterprise-specific IEs (HTTP) from INVEA-TECH in template (template ID: %u)", template_id);
                templ_stats->http_fields_pen = invea_fields[i].pen;
                return;
            }
        }

        // Check enterprise-specific IEs from ntop
        for (i = 0; i < vendor_fields_count && templ_stats->http_fields_pen == 0; ++i) {
            if (template_record_get_field(record, ntop_fields[i].pen, ((struct ipfix_entity) ntop_fields[i]).element_id, NULL) != NULL) {
                MSG_NOTICE(msg_module, "Detected enterprise-specific IEs (HTTP) from ntop in template (template ID: %u)", template_id);
                templ_stats->http_fields_pen = ntop_fields[i].pen;
                return;
            }
        }
    }
}

// For processing template records and option template records
void templates_processor (uint8_t *rec, int rec_len, void *data) {
    struct proxy_processor *proc = (struct proxy_processor *) data;
    struct ipfix_template_record *old_rec = (struct ipfix_template_record *) rec;
    struct ipfix_template_record *new_rec;
    struct ipfix_template *new_templ;
    uint16_t new_rec_len;
    uint16_t element_id, element_length;
    uint32_t pen;
    unsigned int i;

    // Get structure from hashmap that indicates whether template features IPv4 and/or IPv6 fields
    struct templ_stats_elem_t *templ_stats;
    int template_id = (int) ntohs(old_rec->template_id);
    HASH_FIND_INT(proc->plugin_conf->templ_stats, &template_id, templ_stats);

    if (!templ_stats) {
        MSG_ERROR(msg_module, "Could not find entry '%u' in hashmap; using original template", template_id);

        // Copy existing record to new message
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    // Skip further processing if template does not include HTTP IEs (hostname, URL)
    if (templ_stats->http_fields_pen == 0) {
        // Copy existing record to new message
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    // Obtain the total number of fields to add to template (i.e., IPv4 and/or IPv6)
    int orig_fields_to_add = 0;
    if (templ_stats->ipv4) {
        orig_fields_to_add += orig_fields_count;
    }
    if (templ_stats->ipv6) {
        orig_fields_to_add += orig_fields_count;
    }
    if (orig_fields_to_add == 0) {
        // Copy existing record to new message
        memcpy(proc->msg + proc->offset, old_rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;

        return;
    }

    // Add the missing elements to the template:
    //     0. Copy original template record
    new_rec = calloc(1, rec_len + (orig_fields_to_add * 4) + (orig_fields_to_add * 4)); // ID + length = 4 bytes, PEN = 4 bytes
    memcpy(new_rec, old_rec, rec_len);
    new_rec_len = rec_len;

    //     1. Update (new) template record (ID + length = 4 bytes)
    if (templ_stats->ipv4) {
        for (i = 0; i < orig_fields_count; ++i) {
            if (orig_fields_IPv4[i].pen == 0) {
                element_id = htons(orig_fields_IPv4[i].element_id);
            } else {
                element_id = htons(orig_fields_IPv4[i].element_id | 0x8000);
            }
            
            element_length = htons(orig_fields_IPv4[i].length);
            memcpy(((uint8_t *) new_rec) + new_rec_len, &element_id, 2);
            memcpy(((uint8_t *) new_rec) + new_rec_len + 2, &element_length, 2);

            // Update counters
            new_rec->count = htons(ntohs(new_rec->count) + 1);
            new_rec_len += 4;

            // PEN must be added in case of enterprise-specific IEs
            if (orig_fields_IPv4[i].pen != 0) {
                pen = htonl(orig_fields_IPv4[i].pen);
                memcpy(((uint8_t *) new_rec) + new_rec_len, &pen, 4);
                new_rec_len += 4;
            }
        }
    }
    if (templ_stats->ipv6) {
        for (i = 0; i < orig_fields_count; ++i) {
            /*
             * Records can feature one instance of an IE at most. Therefore, if this record
             * features IPv4 data as well, we assume that the port number fields have already
             * been included. As such, we can skip adding them here again for IPv6.
             */
            if (templ_stats->ipv4 && is_port_number_field(orig_fields_IPv6[i].element_id)) {
                continue;
            }

            if (orig_fields_IPv6[i].pen == 0) {
                element_id = htons(orig_fields_IPv6[i].element_id);
            } else {
                element_id = htons(orig_fields_IPv6[i].element_id | 0x8000);
            }
            
            element_length = htons(orig_fields_IPv6[i].length);
            memcpy(((uint8_t *) new_rec) + new_rec_len, &element_id, 2);
            memcpy(((uint8_t *) new_rec) + new_rec_len + 2, &element_length, 2);

            // Update counters
            new_rec->count = htons(ntohs(new_rec->count) + 1);
            new_rec_len += 4;

            // PEN must be added in case of enterprise-specific IEs
            if (orig_fields_IPv6[i].pen != 0) {
                pen = htonl(orig_fields_IPv6[i].pen);
                memcpy(((uint8_t *) new_rec) + new_rec_len, &pen, 4);
                new_rec_len += 4;
            }
        }
    }

    //     2. Generate new template and store it in template manager
    int template_id_new = (int) ntohs(new_rec->template_id);
    proc->key->tid = template_id_new;
    new_templ = tm_add_template(proc->plugin_conf->tm, (void *) new_rec, TEMPL_MAX_LEN, proc->type, proc->key);
    if (new_templ) {
        MSG_NOTICE(msg_module, "Added new template to template manager (ODID: %u, template ID: %u)", proc->key->odid, proc->key->tid);
    } else {
        MSG_ERROR(msg_module, "Failed to add template to template manager");
    }

    //     3. Add new record to message
    memcpy(proc->msg + proc->offset, new_rec, new_rec_len);
    proc->offset += new_rec_len;
    proc->length += new_rec_len;

    // Add new template (ID) to hashmap (templ_stats), with same information as 'old' template (ID)
    struct templ_stats_elem_t *templ_stats_new;
    HASH_FIND_INT(proc->plugin_conf->templ_stats, &template_id_new, templ_stats_new);
    if (templ_stats_new) {
        templ_stats_new->ipv4 = templ_stats->ipv4;
        templ_stats_new->ipv6 = templ_stats->ipv6;
    } else {
        templ_stats_new = malloc(sizeof(struct templ_stats_elem_t));
        templ_stats_new->id = template_id_new;
        templ_stats_new->ipv4 = templ_stats->ipv4;
        templ_stats_new->ipv6 = templ_stats->ipv6;
        HASH_ADD_INT(proc->plugin_conf->templ_stats, id, templ_stats_new);
    }

    free(new_rec);
}

// For processing data records
void data_processor (uint8_t *rec, int rec_len, struct ipfix_template *templ, void *data) {
    struct proxy_processor *proc = (struct proxy_processor *) data;
    uint16_t *msg_data;
    uint8_t *p;
    unsigned int i, j;
    int ret;

    // Get structure from hashmap that indicates whether template features IPv4 and/or IPv6 fields
    struct templ_stats_elem_t *templ_stats;
    int template_id = (int) templ->template_id;
    HASH_FIND_INT(proc->plugin_conf->templ_stats, &template_id, templ_stats);

    if (!templ_stats) {
        MSG_ERROR(msg_module, "Could not find entry '%u' in hashmap; using original data record", template_id);
        return;
    }

    // Skip further processing if template does not include HTTP IEs (hostname, URL)
    if (templ_stats->http_fields_pen == 0) {
        // Copy original data record
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;
        return;
    }

    // Check whether and if, which, port number field with proxy port number can be found in this data record
    int proxy_port_field_id = 0; // Stores ID of field with proxy port (or '-1' in case of no proxy)
    for (i = 0; i < port_number_fields_count; ++i) {
        // Read (source/destination) port number
        if ((ret = template_contains_field(templ, port_number_fields[i].element_id)) == -1) {
            continue;
        }
        message_get_data((uint8_t **) &msg_data, rec + ret, 2); // Port number fields (see port_number_fields) are 2 bytes in size

        // Check whether (source/destination) port number is a proxy port number
        for (j = 0; j < sizeof(proxy_ports) / sizeof(int); ++j) {
            if (ntohs((uint16_t) *msg_data) == proxy_ports[j]) {
                proxy_port_field_id = port_number_fields[i].element_id;
                break;
            }
        }

        free(msg_data);

        // Skip if port number field with proxy port number has already been found
        if (proxy_port_field_id) {
            break;
        }
    }

    // Skip further processing if record does not feature proxy traffic
    if (!proxy_port_field_id) {
        // Copy original data record
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;

        // Add empty 'orig' fields. Field order: <src_port, src_IP_addr, dst_port, dst_IP_addr>
        if (templ_stats->ipv4) {
            for (i = 0; i < orig_fields_count; ++i) {
                memset(proc->msg + proc->offset, 0, orig_fields_IPv4[i].length);
                proc->offset += orig_fields_IPv4[i].length;
                proc->length += orig_fields_IPv4[i].length;
            }
        }
        if (templ_stats->ipv6) {
            for (i = 0; i < orig_fields_count; ++i) {
                /*
                 * Records can feature one instance of an IE at most. Therefore, if this record
                 * features IPv4 data as well, we assume that the port number fields have already
                 * been included. As such, we can skip adding them here again for IPv6.
                 */
                if (templ_stats->ipv4 && is_port_number_field(orig_fields_IPv6[i].element_id)) {
                    continue;
                }

                memset(proc->msg + proc->offset, 0, orig_fields_IPv6[i].length);
                proc->offset += orig_fields_IPv6[i].length;
                proc->length += orig_fields_IPv6[i].length;
            }
        }

        return;
    }

    // Obtain pointer to which HTTP fields to use (from which exporter vendor)
    struct ipfix_entity *http_fields = pen_to_enterprise_fields(templ_stats->http_fields_pen);

    // Retrieve HTTP hostname
    char http_hostname[64];
    ret = template_contains_field(templ, http_fields[0].element_id | 0x8000);
    message_get_data((uint8_t **) &msg_data, rec + ret, http_fields[0].length);
    memcpy(http_hostname, msg_data, http_fields[0].length);
    http_hostname[http_fields[0].length] = '\0';
    free(msg_data);

    // Retrieve HTTP URL
    char http_url[64];
    ret = template_contains_field(templ, http_fields[1].element_id | 0x8000);
    message_get_data((uint8_t **) &msg_data, rec + ret, http_fields[1].length);
    memcpy(http_url, msg_data, http_fields[1].length);
    http_url[http_fields[1].length] = '\0';
    free(msg_data);

    // Check whether HTTP host is not stored in the 'httpHost' field and must be retrieved from 'httpUrl' field
    if (strcmp(http_hostname, "") == 0) {
        // Check whether the URL contains a protocol specification (e.g., 'http://'). If so, strip it.
        if ((p = (uint8_t *) strstr(http_url, "://")) != NULL) {
            memcpy(http_hostname, p + 3, strlen(http_url) - (p - (uint8_t *) &http_url[0])); // '+1' is to ignore '://'
        } else {
            memcpy(http_hostname, http_url, 64);
        }

        // Check whether the URL (now copied to 'http_hostname') contains a path as well. If so, strip it.
        if ((p = (uint8_t *) strstr(http_hostname, "/")) != NULL) {
            memcpy(http_hostname, http_hostname, p - (uint8_t *) &http_hostname[0] - 1); // '-1' is to ignore '/'
        } else {
            memcpy(http_hostname, http_hostname, 64);
        }
    }

    // Skip further processing if hostname information is not available or hostname can never be a valid FQDN
    if (strcmp(http_hostname, "") == 0 || strstr(http_hostname, ".") == NULL) {
        // Copy original data record
        memcpy(proc->msg + proc->offset, rec, rec_len);
        proc->offset += rec_len;
        proc->length += rec_len;

        // Add empty 'orig' fields. Field order: <src_port, src_IP_addr, dst_port, dst_IP_addr>
        if (templ_stats->ipv4) {
            for (i = 0; i < orig_fields_count; ++i) {
                memset(proc->msg + proc->offset, 0, orig_fields_IPv4[i].length);
                proc->offset += orig_fields_IPv4[i].length;
                proc->length += orig_fields_IPv4[i].length;
            }
        }
        if (templ_stats->ipv6) {
            for (i = 0; i < orig_fields_count; ++i) {
                /*
                 * Records can feature one instance of an IE at most. Therefore, if this record
                 * features IPv4 data as well, we assume that the port number fields have already
                 * been included. As such, we can skip adding them here again for IPv6.
                 */
                if (templ_stats->ipv4 && is_port_number_field(orig_fields_IPv6[i].element_id)) {
                    continue;
                }

                memset(proc->msg + proc->offset, 0, orig_fields_IPv6[i].length);
                proc->offset += orig_fields_IPv6[i].length;
                proc->length += orig_fields_IPv6[i].length;
            }
        }

        return;
    }

    // Check whether 'httpHost' also contains a port number (80: default port number)
    int port_number = 80; // Default value
    if ((p = (uint8_t *) strstr(http_hostname, ":")) != NULL) {
        // Extract port number
        char port_number_string[5]; // Port number can feature 5 characters at most
        memcpy(port_number_string, p + 1, strlen(http_hostname) - (p - (uint8_t *) &http_hostname[0])); // '+1' is to ignore ':'
        port_number = atoi(port_number_string);

        // Remove port number from hostname
        http_hostname[p - (uint8_t *) &http_hostname[0]] = '\0';
    }

    // Prepare processing structure
    struct proxy_ares_processor *ares_proc = (struct proxy_ares_processor *) calloc(1, sizeof(struct proxy_ares_processor));
    ares_proc->proc = proc;
    ares_proc->templ = templ;
    ares_proc->orig_rec = rec;
    ares_proc->orig_rec_len = rec_len;
    ares_proc->port_number = port_number;
    ares_proc->proxy_port_field_id = proxy_port_field_id;
    ares_proc->http_hostname = malloc(strlen(http_hostname));
    strcpy(ares_proc->http_hostname, http_hostname);

    // Perform asynchronous domain name resolution
    if (templ_stats->ipv4) {
        ares_gethostbyname(*proc->ares_chan, http_hostname, AF_INET, ares_cb, ares_proc);
    } else {
        ares_gethostbyname(*proc->ares_chan, http_hostname, AF_INET6, ares_cb, ares_proc);
    }
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
int intermediate_init (char *params, void *ip_config, uint32_t ip_id, struct ipfix_template_mgr *template_mgr, void **config) {
    struct proxy_config *conf;

    conf = (struct proxy_config *) malloc(sizeof(*conf));
    if (!conf) {
        MSG_ERROR(msg_module, "Unable to allocate memory (%s:%d)", __FILE__, __LINE__);
        return -1;
    }

    conf->params = params;
    conf->ip_config = ip_config;
    conf->ip_id = ip_id;
    conf->tm = template_mgr;

    // Initialize c-ares
    if ((conf->ares_status = ares_init(&conf->ares_chan)) != ARES_SUCCESS){
        MSG_ERROR(msg_module, "Unable to initialize c-ares");
        return 1;
    }

    // Initialize (empty) hashmap
    conf->templ_stats = NULL;

    *config = conf;

    MSG_NOTICE(msg_module, "Successfully initialized");

    // Plugin successfully initialized
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
int intermediate_process_message (void *config, void *message) {
    struct proxy_config *conf;
    struct proxy_processor proc;
    struct ipfix_message *msg, *new_msg;
    struct ipfix_template *templ, *new_templ;
    struct input_info_network *info;
    uint16_t prev_offset;
    uint32_t tsets = 0, otsets = 0;
    unsigned int i, new_i;

    conf = (struct proxy_config *) config;
    msg = (struct ipfix_message *) message;
    info = (struct input_info_network *) msg->input_info;

    MSG_DEBUG(msg_module, "Received IPFIX message...");

    // Check whether source was closed
    if (msg->source_status == SOURCE_STATUS_CLOSED) {
        MSG_WARNING(msg_module, "Source closed; skipping IPFIX message...");
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /*
     * Check whether this is an IPFIX message. Note that NetFlow v5/v9 and sFlow
     * packets are converted to IPFIX within the input plugins. Ignore this message
     * in case it is not an IPFIX message (v10).
     */
    if (msg->pkt_header->version != htons(IPFIX_VERSION)) {
        MSG_WARNING(msg_module,
                "Unexpected IPFIX version detected (%X); skipping IPFIX message...", msg->pkt_header->version);
        pass_message(conf->ip_config, msg);
        return 0;
    }

    /*
     * Allocate memory for new message (every record is 4 bytes in size). We allocate enough memory
     * here for both IPv4 and IPv6 fields (see '* 2' in statement below).
     */
    int new_msg_length = ntohs(msg->pkt_header->length)
            + orig_fields_count * 2 * 4 * (msg->templ_records_count + msg->opt_templ_records_count)
            + msg->data_records_count * 12  // IPv4 orig fields (2 + 4 + 2 + 4)
            + msg->data_records_count * 36; // IPv6 orig fields (2 + 16 + 2 + 16)
    proc.msg = calloc(1, new_msg_length);
    if (!proc.msg) {
        MSG_ERROR(msg_module, "Unable to allocate memory (%s:%d)", __FILE__, __LINE__);
        return 1;
    }

    // Allocate memory for new IPFIX message
    new_msg = calloc(1, sizeof(struct ipfix_message));
    if (!new_msg) {
        MSG_ERROR(msg_module, "Unable to allocate memory (%s:%d)", __FILE__, __LINE__);
        free(proc.msg);
        return 1;
    }

    // Copy original IPFIX header
    memcpy(proc.msg, msg->pkt_header, IPFIX_HEADER_LENGTH);
    new_msg->pkt_header = (struct ipfix_header *) proc.msg;
    proc.offset = IPFIX_HEADER_LENGTH;

    // Initialize processing structure
    proc.ares_chan = &conf->ares_chan;
    proc.odid = msg->input_info->odid;
    proc.key = tm_key_create(info->odid, conf->ip_id, 0); // Template ID (0) will be overwritten in a later stage
    proc.plugin_conf = config;

    // Process templates
    MSG_DEBUG(msg_module, "Processing template sets...");
    proc.type = TM_TEMPLATE;
    for (i = 0; i < 1024 && msg->templ_set[i]; ++i) {
        prev_offset = proc.offset;

        /* Determine IP versions used within each template set and store result in hashmap. Also,
         * determine exporter PEN based on presence of certain enterprise-specific IEs.
         */
        template_set_process_records(msg->templ_set[i], proc.type, &templates_stat_processor, (void *) &proc);

        // Add template set header, and update offset and length
        memcpy(proc.msg + proc.offset, &(msg->templ_set[i]->header), 4);
        proc.offset += 4;
        proc.length = 4;

        // Process all template set records
        template_set_process_records(msg->templ_set[i], proc.type, &templates_processor, (void *) &proc);

        // Check whether a new template set was added by 'templates_processor'
        if (proc.offset == prev_offset + 4) { // No new template set record was added
            proc.offset = prev_offset;
        } else { // New template set was added; add it to data structure as well
            new_msg->templ_set[tsets] = (struct ipfix_template_set *) ((uint8_t *) proc.msg + prev_offset);
            new_msg->templ_set[tsets]->header.length = htons(proc.length);
            tsets++;
        }
    }

    // Demarcate end of templates in set
    new_msg->templ_set[tsets] = NULL;

    // Process option templates
    MSG_DEBUG(msg_module, "Processing option template sets...");
    proc.type = TM_OPTIONS_TEMPLATE;
    for (i = 0; i < 1024 && msg->opt_templ_set[i]; ++i) {
        prev_offset = proc.offset;

        // Add template set header, and update offset and length
        memcpy(proc.msg + proc.offset, &(msg->opt_templ_set[i]->header), 4);
        proc.offset += 4;
        proc.length = 4;

        template_set_process_records((struct ipfix_template_set *) msg->opt_templ_set[i], proc.type, &templates_processor, (void *) &proc);

        // Check whether a new options template set was added by 'templates_processor'
        if (proc.offset == prev_offset + 4) {
            proc.offset = prev_offset;
        } else { // New options template set was added; add it to data structure as well
            new_msg->opt_templ_set[otsets] = (struct ipfix_options_template_set *) ((uint8_t *) proc.msg + prev_offset);
            new_msg->opt_templ_set[otsets]->header.length = htons(proc.length);
            otsets++;
        }
    }

    // Demarcate end of option templates in set
    new_msg->opt_templ_set[otsets] = NULL;

    // Process data records
    MSG_DEBUG(msg_module, "Processing data sets...");
    for (i = 0, new_i = 0; i < 1024 && msg->data_couple[i].data_set; ++i) {
        templ = msg->data_couple[i].data_template;

        /*
         * Skip processing in case there is no template available for this data set. This may
         * be caused by a problem in a previous intermediate plugin.
         */
        if (!templ) {
            MSG_WARNING(msg_module, "Data couple features no template (set: %u)", i);
            continue;
        }

        proc.key->tid = templ->template_id;
        new_templ = tm_get_template(conf->tm, proc.key);
        if (!new_templ) {
            // MSG_WARNING(msg_module, "Could not retrieve template from template manager (ODID: %u, IP ID: %u, template ID: %u)", info->odid, conf->ip_id, templ->template_id);
            // Assume that template was not modified by this plugin if new template was not registered in template manager
            new_templ = templ;
        }

        // Add data set header, and update offset and length
        memcpy(proc.msg + proc.offset, &(msg->data_couple[i].data_set->header), 4);
        proc.offset += 4;
        proc.length = 4;

        // Update 'data_couple' by adjusting pointers to updated data structures
        new_msg->data_couple[new_i].data_set = ((struct ipfix_data_set *) ((uint8_t *) proc.msg + proc.offset - 4));
        new_msg->data_couple[new_i].data_template = new_templ;

        // Increase number of references to template
        new_templ->last_message = templ->last_message;
        new_templ->last_transmission = templ->last_transmission;
        tm_template_reference_inc(new_templ);

        data_set_process_records(msg->data_couple[i].data_set, templ, &data_processor, (void *) &proc);

        // Wait for all domain name resolutions to have completed
        ares_wait(conf->ares_chan);

        // Add padding bytes, if necessary
        if (proc.length % 4 != 0) {
            int padding_size = 4 - (proc.length % 4);
            MSG_DEBUG(msg_module, "Data set needs %u bytes of padding (raw length: %u)", 4 - (proc.length % 4), proc.length);

            // FIXME Check RFC 7011: "The padding length MUST be shorter than any allowable record in this Set."
            memset(proc.msg + proc.offset, 0, padding_size);
            proc.offset += padding_size;
            proc.length += padding_size;
        }

        new_msg->data_couple[new_i].data_set->header.length = htons(proc.length);
        new_msg->data_couple[new_i].data_set->header.flowset_id = htons(new_msg->data_couple[new_i].data_template->template_id);

        /*
         * We use a second loop index for cases where a data_couple does not feature a template,
         * so not 'gaps' will be present in the list of data sets.
         */
        ++new_i;
    }

    // Demarcate end of data records in set
    new_msg->data_couple[new_i].data_set = NULL;

    // Don't send empty IPFIX messages (i.e., message includes no templates, option templates, or data records)
    if (proc.offset == IPFIX_HEADER_LENGTH) {
        MSG_WARNING(msg_module, "Empty IPFIX message detected; dropping message");
        free(proc.key);
        free(proc.msg);
        free(new_msg);
        drop_message(conf->ip_config, message);
        return 0;
    }

    // Update IPFIX message length (in header)
    new_msg->pkt_header->length = htons(proc.offset);
    new_msg->input_info = msg->input_info;
    new_msg->templ_records_count = msg->templ_records_count;
    new_msg->opt_templ_records_count = msg->opt_templ_records_count;
    new_msg->data_records_count = msg->data_records_count;
    new_msg->source_status = msg->source_status;

    free(proc.key);

    drop_message(conf->ip_config, message);
    pass_message(conf->ip_config, (void *) new_msg);

    MSG_DEBUG(msg_module, "Processing IPFIX message done");
    return 0;
}

/**
 * \brief Close intermediate Plugin
 *
 * \param[in] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_close (void *config) {
    struct proxy_config *conf;
    conf = (struct proxy_config *) config;

    // Clean up templ_stats hashmap
    struct templ_stats_elem_t *current_templ_stats, *tmp;
    HASH_ITER(hh, conf->templ_stats, current_templ_stats, tmp) {
        HASH_DEL(conf->templ_stats, current_templ_stats);
        free(current_templ_stats); 
    }

    free(conf);

    ares_destroy(conf->ares_chan);
    ares_library_cleanup();

    return 0;
}
