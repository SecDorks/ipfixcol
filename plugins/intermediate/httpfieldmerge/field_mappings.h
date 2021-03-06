/*
 * \file field_mappings.h
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

#ifndef HTTPFIELDMERGE_FIELD_MAPPINGS_H_
#define HTTPFIELDMERGE_FIELD_MAPPINGS_H_

#include "fields.h"

struct field_mapping {
    struct ipfix_entity from;
    struct ipfix_entity to;
};

static struct field_mapping invea_field_mappings[] = {
    { invea_http_hostname,      target_http_hostname },
    { invea_http_url,           target_http_url },
    { invea_http_user_agent,    target_http_user_agent }
};
static struct field_mapping masaryk_field_mappings[] = {
    { masaryk_http_hostname,    target_http_hostname },
    { masaryk_http_url,         target_http_url },
    { masaryk_http_user_agent,  target_http_user_agent }
};
static struct field_mapping ntop_field_mappings[] = {
    { ntop_http_hostname,       target_http_hostname },
    { ntop_http_url,            target_http_url },
    { ntop_http_user_agent,     target_http_user_agent }
};
static struct field_mapping ntopv9_field_mappings[] = {
    { ntop_http_hostname_v9,    target_http_hostname },
    { ntop_http_url_v9,         target_http_url },
    { ntop_http_user_agent_v9,  target_http_user_agent }
};
static struct field_mapping rs_field_mappings[] = {
    { rs_http_hostname,         target_http_hostname },
    { rs_http_url,              target_http_url },
    { rs_http_user_agent,       target_http_user_agent }
};
static struct field_mapping secureme2_field_mappings[] = {
    { secureme2_http_hostname,  target_http_hostname },
    { secureme2_http_url,       target_http_url },
    { secureme2_http_user_agent,target_http_user_agent }
};

#endif /* HTTPFIELDMERGE_FIELD_MAPPINGS_H_ */
