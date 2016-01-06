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

#ifndef HTTPFIELDMERGE_H_
#define HTTPFIELDMERGE_H_

#include <ipfixcol.h>

#include "uthash.h"

/* Identifier for MSG_* macros */
#define msg_module "httpfieldmerge"

#define NFV9_CONVERSION_PEN     0xFFFFFFFF
#define TEMPL_MAX_LEN           100000

struct templ_stats_elem_t {
    UT_hash_handle hh;              /* Hash handle for internal hash functioning */
    uint32_t http_fields_pen;       /* Exporter PEN in case template contains HTTP-related fields */
    int http_fields_pen_determined; /* Indicates whether the PEN belonging HTTP-related has been determined before */
    int id;                         /* Hash key */
};

/* Hash element that contains information on the vendor (and related
 * enterprise-specific fields) of an observation domain.
 */
struct od_stats_elem_t {
    UT_hash_handle hh;              /* Hash handle for internal hash functioning */
    tset_callback_f tset_proc;      /* Processor for (option) template sets */
    dset_callback_f dset_proc;      /* Processor for data sets */
    uint32_t od_id;                 /* Hash key - component 1 */
    uint32_t ip_id;                 /* Hash key - component 2 */
};

/* Structure used as key in od_stats_elem_t */
struct od_stats_key_t {
    uint32_t od_id;
    uint32_t ip_id;
};

/* Stores plugin's internal configuration */
struct httpfieldmerge_config {
    char *params;
    void *ip_config;
    uint32_t ip_id;
    struct ipfix_template_mgr *tm;

    /* Hashmap for storing the IP version used in every template by template ID. We
     * place this structure in proxy_config rather than proxy_processor, since
     * it should be persistent between various IPFIX messages (and proxy processor
     * is reset for every IPFIX message).
     */
    struct templ_stats_elem_t *templ_stats;

    /* Hashmap for storing callback processor references for every tuple of ODID and
     * IP address, so for every unique source.
     */
    uint16_t od_stats_key_len;
    struct od_stats_elem_t *od_stats;
};

struct httpfieldmerge_processor {
    int type;
    uint8_t *msg;
    uint16_t allocated_msg_len, offset;
    uint32_t length, odid;
    
    struct httpfieldmerge_config *plugin_conf; /* Pointer to proxy_config, such that we don't have to store some pointers twice */
    struct ipfix_template_key *key; /* Stores the key of a newly added template within the template manager */
};

#endif /* HTTPFIELDMERGE_H_ */
