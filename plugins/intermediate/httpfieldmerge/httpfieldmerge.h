/*
 * \file httpfieldmerge.h
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'httpfieldmerge' intermediate plugin.
 *
 * Intermediate plugin for IPFIXcol that merges HTTP-related fields from various vendors
 * into one unified set, such that analysis applications can always rely on the unified
 * set of fields. The following fields are currently supported:
 *
 *     - HTTP hostname
 *     - HTTP URL
 *
 * Specifically, this plugin performs only a single task:
 *
 *     - Replace the IE definitions of HTTP-related fields with those of the unified
 *          set of fields. As such, only templates are modified (and data records are
 *          not).
 *
 * HTTP-related fields from the following vendors are currently supported:
 *
 *     - INVEA-TECH,    PEN: 39499
 *     - ntop,          PEN: 35632
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

#ifndef HTTPFIELDMERGE_H_
#define HTTPFIELDMERGE_H_

#include <ipfixcol.h>

#include "uthash.h"

#define TEMPL_MAX_LEN 100000
#define TARGET_FIELD_PEN 44913

// IPFIX Information Elements used within this plugin (PEN, ID, length (bytes), name)
#define inveaHttpHost   { 39499,   1, 32,  "inveaHttpHost" }
#define inveaHttpUrl    { 39499,   2, 64,  "inveaHttpUrl" }

#define ntopHttpHost    { 35632, 187, 32,  "ntopHttpHost" }
#define ntopHttpUrl     { 35632, 180, 64,  "ntopHttpUrl" }

#define rsHttpHost      { 44913,   1, 20,  "rsHttpHost" }
#define rsHttpUrl       { 44913,   2, 21,  "rsHttpUrl" }

struct ipfix_entity {
    uint16_t pen;
    uint16_t element_id;
    int length;
    char *entity_name;
};

static struct ipfix_entity invea_fields[] = {
    inveaHttpHost, inveaHttpUrl
};
static struct ipfix_entity ntop_fields[] = {
    ntopHttpHost, ntopHttpUrl
};
static struct ipfix_entity rs_fields[] = {
    rsHttpHost, rsHttpUrl
};
#define vendor_fields_count         2

struct field_mapping {
    struct ipfix_entity from;
    struct ipfix_entity to;
};

static struct field_mapping invea_field_mappings[] = {
    {inveaHttpHost, rsHttpHost},
    {inveaHttpUrl,  rsHttpUrl}
};
static struct field_mapping ntop_field_mappings[] = {
    {ntopHttpHost,  rsHttpHost},
    {ntopHttpUrl,   rsHttpUrl}
};

struct templ_stats_elem_t {
    int id;                 // Hash key
    int http_fields_pen;    // Exporter PEN in case template contains HTTP-related fields
    UT_hash_handle hh;      // Hash handle for internal hash functioning
};

// Stores plugin's internal configuration
struct httpfieldmerge_config {
    char *params;
    void *ip_config;
    uint32_t ip_id;
    struct ipfix_template_mgr *tm;

    /*
     * Hashmap for storing the IP version used in every template by template ID. We
     * place this structure in proxy_config rather than proxy_processor, since
     * it should be persistent between various IPFIX messages (and proxy processor)
     * is reset for every IPFIX message.
     */
    struct templ_stats_elem_t *templ_stats;
};

struct httpfieldmerge_processor {
    uint8_t *msg;
    uint16_t offset;
    uint32_t length, odid;
    int type;
    
    struct httpfieldmerge_config *plugin_conf; // Pointer to proxy_config, such that we don't have to store some pointers twice
    struct ipfix_template_key *key; // Stores the key of a newly added template within the template manager
};

#endif /* HTTPFIELDMERGE_H_ */
