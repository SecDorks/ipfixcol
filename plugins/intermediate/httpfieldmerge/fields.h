/*
 * \file fields.h
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

#ifndef HTTPFIELDMERGE_FIELDS_H_
#define HTTPFIELDMERGE_FIELDS_H_

#include "pens.h"

struct ipfix_entity {
    uint32_t pen;
    uint16_t element_id;
};

/* IPFIX Information Elements used within this plugin (PEN, ID) */
/* Cisco uses multiple instances (4) of field e9id12235 for exporting
   HTTP-related information, always in the following order:
        - Instance 1: URL
        - Instance 2: hostname
        - Instance 3: user agent string
        - Instance 4: unknown?
 */
#define cisco_http_hostname     { CISCO_PEN, 12235 }
#define cisco_http_url          { CISCO_PEN, 12235 }
#define cisco_http_user_agent   { CISCO_PEN, 12235 }
#define cisco_http_unknown      { CISCO_PEN, 12235 }
#define cisco_field_count       4

#define invea_http_hostname     { INVEA_PEN,  1 }
#define invea_http_url          { INVEA_PEN,  2 }
#define invea_http_user_agent   { INVEA_PEN, 20 }
#define invea_field_count       3

#define masaryk_http_hostname   { MASARYK_PEN, 501 }
#define masaryk_http_url        { MASARYK_PEN, 502 }
#define masaryk_http_user_agent { MASARYK_PEN, 504 }
#define masaryk_field_count     3

#define ntop_http_hostname      { NTOP_PEN, 187 }
#define ntop_http_url           { NTOP_PEN, 180 }
#define ntop_http_user_agent    { NTOP_PEN, 183 }
#define ntop_field_count        3

#define ntop_http_hostname_v9   { NFV9_CONVERSION_PEN, 24891 } /* Original ID: 57659 */
#define ntop_http_url_v9        { NFV9_CONVERSION_PEN, 24884 } /* Original ID: 57652 */
#define ntop_http_user_agent_v9 { NFV9_CONVERSION_PEN, 24887 } /* Original ID: 57655 */

#define rs_http_hostname        { RS_PEN, 20 }
#define rs_http_url             { RS_PEN, 21 }
#define rs_http_user_agent      { RS_PEN, 22 }
#define rs_field_count          3

#define secureme2_http_hostname { SECUREME2_PEN, 1 }
#define secureme2_http_url      { SECUREME2_PEN, 2 }
#define secureme2_http_user_agent   { SECUREME2_PEN, 3 }
#define secureme2_field_count   3

#define target_http_hostname    { TARGET_PEN, 20 }
#define target_http_url         { TARGET_PEN, 21 }
#define target_http_user_agent  { TARGET_PEN, 22 }
#define target_unknown          { TARGET_PEN, 12345 }
#define target_field_count      4

extern struct ipfix_entity cisco_fields[];
extern struct ipfix_entity invea_fields[];
extern struct ipfix_entity masaryk_fields[];
extern struct ipfix_entity ntop_fields[];
extern struct ipfix_entity ntopv9_fields[];
extern struct ipfix_entity rs_fields[];
extern struct ipfix_entity secureme2_fields[];
extern struct ipfix_entity target_fields[];

#endif /* HTTPFIELDMERGE_FIELDS_H_ */
