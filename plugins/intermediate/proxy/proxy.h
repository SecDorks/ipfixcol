/*
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
 * Author:  Rick Hofstede <mail&rickhofstede.nl>
 *
 */

#ifndef PROXY_H_
#define PROXY_H_

#include <ares.h>
#include <netdb.h>
#include <ipfixcol.h>

#include "uthash.h"

#define TEMPL_MAX_LEN 100000

// IPFIX Information Elements used within this plugin (PEN, ID, length (bytes), name)
#define sourceTransportPort             { 0,  7,   2,  "sourceTransportPort" }
#define sourceIPv4Address               { 0,  8,   4,  "sourceIPv4Address" }
#define destinationTransportPort        { 0,  11,  2,  "destinationTransportPort" }
#define destinationIPv4Address          { 0,  12,  4,  "destinationIPv4Address" }
#define sourceIPv6Address               { 0,  27, 16,  "sourceIPv6Address" }
#define destinationIPv6Address          { 0,  28, 16,  "destinationIPv6Address"}

#define origSourceTransportPort         { 44913, 10,  2,  "origSourceTransportPort" }
#define origSourceIPv4Address           { 44913, 11,  4,  "origSourceIPv4Address" }
#define origDestinationTransportPort    { 44913, 12,  2,  "origDestinationTransportPort" }
#define origDestinationIPv4Address      { 44913, 13,  4,  "origDestinationIPv4Address" }
#define origSourceIPv6Address           { 44913, 14, 16,  "origSourceIPv6Address" }
#define origDestinationIPv6Address      { 44913, 15, 16,  "origDestinationIPv6Address" }

#define inveaHttpHost                   { 39499,   1, 32,  "inveaHttpHost" }
#define inveaHttpUrl                    { 39499,   2, 64,  "inveaHttpUrl" }

#define ntopHttpHost                    { 35632, 187, 32,  "ntopHttpHost" }
#define ntopHttpUrl                     { 35632, 180, 64,  "ntopHttpUrl" }

struct ipfix_entity {
    uint16_t pen;
    uint16_t element_id;
    int length;
    char *entity_name;
};

static struct ipfix_entity port_number_fields[] = {
    sourceTransportPort, destinationTransportPort
};
#define port_number_fields_count    2

static struct ipfix_entity source_fields[] = {
    sourceTransportPort, sourceIPv4Address, sourceIPv6Address, origSourceTransportPort, origSourceIPv4Address, origSourceIPv6Address
};
#define source_fields_count         6

static struct ipfix_entity orig_fields_IPv4[] = {
    origSourceTransportPort, origSourceIPv4Address, origDestinationTransportPort, origDestinationIPv4Address
};
static struct ipfix_entity orig_fields_IPv6[] = {
    origSourceTransportPort, origSourceIPv6Address, origDestinationTransportPort, origDestinationIPv6Address
};
#define orig_fields_count           4

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

static struct field_mapping IPv4_field_mappings[] = {
    {sourceTransportPort,       origSourceTransportPort},
    {sourceIPv4Address,         origSourceIPv4Address},
    {destinationTransportPort,  origDestinationTransportPort},
    {destinationIPv4Address,    origDestinationIPv4Address}
};
static struct field_mapping IPv6_field_mappings[] = {
    {sourceTransportPort,       origSourceTransportPort},
    {sourceIPv6Address,         origSourceIPv6Address},
    {destinationTransportPort,  origDestinationTransportPort},
    {destinationIPv6Address,    origDestinationIPv6Address}
};
#define mapping_count               4

// Detection of these ports will trigger domain name resolution
static int proxy_ports[] = {
    3128, 8080
};

struct templ_stats_elem_t {
    int id;                 // Hash key
    int http_fields_pen;    // Exporter PEN in case template contains HTTP-related fields
    int ipv4;               // Indicates whether template contains IPv4 address fields
    int ipv6;               // Indicates whether template contains IPv6 address fields
    UT_hash_handle hh;      // Hash handle for internal hash functioning
};

// Stores plugin's internal configuration
struct proxy_config {
    char *params;
    void *ip_config;
    uint32_t ip_id;
    struct ipfix_template_mgr *tm;

    /*
     * Variables for use by c-ares
     */
    int ares_status;
    ares_channel ares_chan;

    /*
     * Hashmap for storing the IP version used in every template by template ID. We
     * place this structure in proxy_config rather than proxy_processor, since
     * it should be persistent between various IPFIX messages (and proxy processor)
     * is reset for every IPFIX message.
     */
    struct templ_stats_elem_t *templ_stats;
};

struct proxy_processor {
    uint8_t *msg;
    uint16_t offset;
    uint32_t length, odid;
    int type;

    ares_channel *ares_chan; // Channel used for domain name resolutions
    
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
