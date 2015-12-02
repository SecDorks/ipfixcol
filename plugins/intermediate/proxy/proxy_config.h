/*
 * \file proxy_config.h
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

#ifndef PROXY_CONFIG_H_
#define PROXY_CONFIG_H_

#include "proxy.h"

#define DEFAULT_STAT_INTERVAL   0
#define HTTP_FIELD_WORKING_SIZE 65
#define NFV9_CONVERSION_PEN     0xFFFFFFFF
#define TEMPL_MAX_LEN           100000
#define VAR_LEN_ELEM_LEN        65535

/* IPFIX Information Elements used within this plugin (PEN, ID, length (bytes), name) */
#define sourceTransportPort             { 0,       7,  2 }
#define sourceIPv4Address               { 0,       8,  4 }
#define destinationTransportPort        { 0,      11,  2 }
#define destinationIPv4Address          { 0,      12,  4 }
#define sourceIPv6Address               { 0,      27, 16 }
#define destinationIPv6Address          { 0,      28, 16 }

#define origSourceTransportPort         { 44913,  10,  2 }
#define origSourceIPv4Address           { 44913,  11,  4 }
#define origDestinationTransportPort    { 44913,  12,  2 }
#define origDestinationIPv4Address      { 44913,  13,  4 }
#define origSourceIPv6Address           { 44913,  14, 16 }
#define origDestinationIPv6Address      { 44913,  15, 16 }

/* Zero-length fields are fields with variable lengths */
#define inveaHttpHost                   { 39499,   1,  0 }
#define inveaHttpUrl                    { 39499,   2,  0 }

#define ntopHttpHost                    { 35632, 187,  0 }
#define ntopHttpUrl                     { 35632, 180,  0 }

#define rsHttpHost                      { 44913,  20,  0 }
#define rsHttpUrl                       { 44913,  21,  0 }

struct ipfix_ie port_number_fields[] = {
    sourceTransportPort, destinationTransportPort
};
#define port_number_fields_count    2

struct ipfix_ie source_fields[] = {
    sourceTransportPort, sourceIPv4Address, sourceIPv6Address, origSourceTransportPort, origSourceIPv4Address, origSourceIPv6Address
};
#define source_fields_count         6

struct ipfix_ie orig_fields_IPv4[] = {
    origSourceTransportPort, origSourceIPv4Address, origDestinationTransportPort, origDestinationIPv4Address
};
struct ipfix_ie orig_fields_IPv6[] = {
    origSourceTransportPort, origSourceIPv6Address, origDestinationTransportPort, origDestinationIPv6Address
};
#define orig_fields_count           4

struct ipfix_ie invea_fields[] = {
    inveaHttpHost, inveaHttpUrl
};
struct ipfix_ie ntop_fields[] = {
    ntopHttpHost, ntopHttpUrl
};
struct ipfix_ie rs_fields[] = {
    rsHttpHost, rsHttpUrl
};
#define vendor_fields_count         2

struct field_mapping {
    struct ipfix_ie from;
    struct ipfix_ie to;
};

struct field_mapping IPv4_field_mappings[] = {
    {sourceTransportPort,       origSourceTransportPort},
    {sourceIPv4Address,         origSourceIPv4Address},
    {destinationTransportPort,  origDestinationTransportPort},
    {destinationIPv4Address,    origDestinationIPv4Address}
};
struct field_mapping IPv6_field_mappings[] = {
    {sourceTransportPort,       origSourceTransportPort},
    {sourceIPv6Address,         origSourceIPv6Address},
    {destinationTransportPort,  origDestinationTransportPort},
    {destinationIPv6Address,    origDestinationIPv6Address}
};
#define mapping_count               4

/* Detection of these ports will trigger domain name resolution */
int default_proxy_ports[] = {
    3128, 8080
};

#endif /* PROXY_CONFIG_H_ */
