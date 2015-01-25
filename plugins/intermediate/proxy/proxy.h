/*
 * \file proxy.h
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

#ifndef PROXY_H_
#define PROXY_H_

#define ARES_CHANNELS 10

#include <ares.h>
#include <netdb.h>
#include <ipfixcol.h>
#include <libxml/parser.h>

#include "uthash.h"

struct ipfix_entity {
    uint16_t pen;
    uint16_t element_id;
    uint16_t length;
    char *entity_name;
};

struct templ_stats_elem_t {
    int id;                         // Hash key
    uint32_t http_fields_pen;       // Exporter PEN in case template contains HTTP-related fields
    int http_fields_pen_determined; // Indicates whether the PEN belonging HTTP-related has been determined before
    int ipv4;                       // Indicates whether template contains IPv4 address fields
    int ipv6;                       // Indicates whether template contains IPv6 address fields
    UT_hash_handle hh;              // Hash handle for internal hash functioning
};

// Stores plugin's internal configuration
struct proxy_config {
    char *params;
    void *ip_config;
    uint32_t ip_id;
    struct ipfix_template_mgr *tm;
    pthread_t stat_thread;
    uint16_t stat_interval;
    uint8_t stat_done;

    // Variables for use by c-ares
    ares_channel ares_channels[ARES_CHANNELS]; // Stores all c-ares channels
    uint8_t ares_channel_id; // ID of last-used c-ares channel

    /*
     * Hashmap for storing the IP version used in every template by template ID. We
     * place this structure in proxy_config rather than proxy_processor, since
     * it should be persistent between various IPFIX messages (and proxy processor
     * is reset for every IPFIX message).
     */
    struct templ_stats_elem_t *templ_stats;

    /*
     * Will contain the proxy ports used by this plugin, either the default ports,
     * or the ports specified in the plugin's XML configuration.
     */
    unsigned int proxy_port_count;
    int *proxy_ports;
};

struct proxy_processor {
    uint8_t *msg;
    uint16_t offset;
    uint32_t length, odid;
    int type;

    ares_channel *ares_channels; // Channel used for domain name resolutions
    uint8_t *ares_channel_id;
    
    struct proxy_config *plugin_conf; // Pointer to proxy_config, such that we don't have to store some pointers twice
    struct ipfix_template_key *key; // Stores the key of a newly added template within the template manager
};

struct proxy_ares_processor {
    struct proxy_processor *proc;
    struct ipfix_template *templ;

    uint8_t *orig_rec;
    int orig_rec_len;

    char *http_hostname;
    int port_number;

    int proxy_port_field_id;
};

#endif /* PROXY_H_ */
