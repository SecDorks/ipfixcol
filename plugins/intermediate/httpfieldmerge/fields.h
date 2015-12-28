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
#define ciscoHttpHostname       { CISCO_PEN, 12235 }
#define ciscoHttpUrl            { CISCO_PEN, 12235 }
#define ciscoHttpUserAgent      { CISCO_PEN, 12235 }
#define ciscoHttpUnknown        { CISCO_PEN, 12235 }
#define cisco_field_count       4

#define inveaHttpHostname       { INVEA_PEN,  1 }
#define inveaHttpUrl            { INVEA_PEN,  2 }
#define inveaHttpUserAgent      { INVEA_PEN, 20 }
#define invea_field_count       3

#define masarykHttpHostname     { MASARYK_PEN, 501 }
#define masarykHttpUrl          { MASARYK_PEN, 502 }
#define masarykHttpUserAgent    { MASARYK_PEN, 504 }
#define masaryk_field_count     3

#define ntopHttpHostname        { NTOP_PEN, 187 }
#define ntopHttpUrl             { NTOP_PEN, 180 }
#define ntopHttpUserAgent       { NTOP_PEN, 183 }
#define ntop_field_count        3

#define ntopHttpHostnamev9      { NFV9_CONVERSION_PEN, 24891 } /* Original ID: 57659 */
#define ntopHttpUrlv9           { NFV9_CONVERSION_PEN, 24884 } /* Original ID: 57652 */
#define ntopHttpUserAgentv9     { NFV9_CONVERSION_PEN, 24887 } /* Original ID: 57655 */
// #define ntop_field_count        3 (already defined above)

#define rsHttpHostname          { RS_PEN, 20 }
#define rsHttpUrl               { RS_PEN, 21 }
#define rsHttpUserAgent         { RS_PEN, 22 }
#define rs_field_count          3

#define targetHttpHostname      { TARGET_PEN, 20 }
#define targetHttpUrl           { TARGET_PEN, 21 }
#define targetHttpUserAgent     { TARGET_PEN, 22 }

static struct ipfix_entity target_http_hostname =   { TARGET_PEN, 20 };
static struct ipfix_entity target_http_url =        { TARGET_PEN, 21 };
static struct ipfix_entity target_http_user_agent = { TARGET_PEN, 22 };
static struct ipfix_entity target_unknown =         { TARGET_PEN, 65535 };

static struct ipfix_entity cisco_fields[] = {
    ciscoHttpHostname, ciscoHttpUrl, ciscoHttpUserAgent, ciscoHttpUnknown
};
static struct ipfix_entity invea_fields[] = {
    inveaHttpHostname, inveaHttpUrl, inveaHttpUserAgent
};
static struct ipfix_entity masaryk_fields[] = {
    masarykHttpHostname, masarykHttpUrl, masarykHttpUserAgent
};
static struct ipfix_entity ntop_fields[] = {
    ntopHttpHostname, ntopHttpUrl, ntopHttpUserAgent
};
static struct ipfix_entity ntopv9_fields[] = {
    ntopHttpHostnamev9, ntopHttpUrlv9, ntopHttpUserAgentv9
};
static struct ipfix_entity rs_fields[] = {
    rsHttpHostname, rsHttpUrl, rsHttpUserAgent
};

#endif /* HTTPFIELDMERGE_FIELDS_H_ */
