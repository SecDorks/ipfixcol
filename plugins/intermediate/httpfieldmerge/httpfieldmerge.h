/*
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
 * Author:  Rick Hofstede <mail&rickhofstede.nl>
 *
 */

#ifndef HTTPFIELDMERGE_H_
#define HTTPFIELDMERGE_H_

#include <ipfixcol.h>

#include "uthash.h"

#define TEMPL_MAX_LEN 100000
#define TARGET_FIELD_PEN 44913

// IPFIX Information Elements used within this plugin (PEN, ID, length (bytes), name)
#define rsHttpHost      { 44913,   1, 20,  "rsHttpHost" }
#define rsHttpUrl       { 44913,   2, 21,  "rsHttpUrl" }

#define inveaHttpHost   { 39499,   1, 32,  "inveaHttpHost" }
#define inveaHttpUrl    { 39499,   2, 64,  "inveaHttpUrl" }

#define ntopHttpHost    { 35632, 187, 32,  "ntopHttpHost" }
#define ntopHttpUrl     { 35632, 180, 64,  "ntopHttpUrl" }

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
