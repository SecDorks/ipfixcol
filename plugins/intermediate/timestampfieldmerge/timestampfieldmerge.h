/*
 * \file timestampfieldmerge.h
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

#ifndef TIMESTAMPFIELDMERGE_H_
#define TIMESTAMPFIELDMERGE_H_

#include <ipfixcol.h>
#include <time.h>

#include "uthash.h"

/* Identifier for MSG_* macros */
#define msg_module "timestampfieldmerge"

struct ipfix_entity {
    uint32_t pen;
    uint16_t element_id;
    uint16_t length;
};

#define BYTES_4                     4
#define BYTES_8                     8
#define TEMPL_MAX_LEN               100000

#define flowStartSysUpTime          { 0,  22, 4 }
#define flowEndSysUpTime            { 0,  21, 4 }
#define systemInitTimeMilliseconds  { 0, 160, 8 }

#define flowStartMilliseconds       { 0, 152, 8 }
#define flowEndMilliseconds         { 0, 153, 8 }

struct templ_stats_elem_t {
    UT_hash_handle hh;                  /* Hash handle for internal hash functioning */
    uint16_t start_time_field_id;       /* Field ID of start time field that must be converted */
    uint16_t end_time_field_id;         /* Field ID of end time field that must be converted */
    uint16_t sysuptime_field_id;        /* Field ID of system uptime field that should be used in conversion */
    uint32_t od_id;                     /* Hash key - component 1 */
    uint32_t ip_id;                     /* Hash key - component 2 */
    uint16_t template_id;               /* Hash key - component 3 */
};

/* Structure used as key in templ_stats_elem_t */
struct templ_stats_key_t {
    uint32_t od_id;
    uint32_t ip_id;
    uint16_t template_id;
};

/* Stores plugin's internal configuration */
struct plugin_config {
    char *params;
    void *ip_config;
    uint32_t ip_id;
    struct ipfix_template_mgr *tm;

    /* Hashmap for storing information on the presence of certain timestamp fields for
     * every tuple of ODID and IP address, so for every unique source.
     */
    uint16_t templ_stats_key_len;
    struct templ_stats_elem_t *templ_stats;

    /* Field instances */
    struct ipfix_entity field_flowStartSysUpTime;
    struct ipfix_entity field_flowEndSysUpTime;
    struct ipfix_entity field_systemInitTimeMilliseconds;
};

struct processor {
    int type;
    uint8_t *msg;
    uint16_t allocated_msg_len, offset;
    uint32_t length, odid;
    time_t time;
    
    struct plugin_config *plugin_conf;          /* Pointer to plugin_config, such that we don't have to store some pointers twice */
    struct ipfix_template_key *key;             /* Stores the key of a newly added template within the template manager */
    struct ipfix_template *orig_templ;          /* Pointer to original template */
    struct templ_stats_key_t *templ_stats_key;  /* Pointer to templ_stats key */
};

#endif /* TIMESTAMPFIELDMERGE_H_ */
