/*
 * \file ipfixgenerator_config.h
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'IPFIX generator' input plugin.
 *
 * IPFIXcol input plugin for generating semi-random IPFIX traffic. The main
 * purpose of this plugin is performance testing.
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

#ifndef IPFIXGENERATOR_CONFIG_H_
#define IPFIXGENERATOR_CONFIG_H_

/* IPFIX Information Elements used within this plugin (PEN, ID, length (bytes), name) */
#define octetDeltaCount             { 0,      2,    IPFIX_TYPE_UNSIGNED64,      8,  "octetDeltaCount",          1 }
#define packetDeltaCount            { 0,      3,    IPFIX_TYPE_UNSIGNED64,      8,  "packetDeltaCount",         1 }
#define protocolIdentifier          { 0,      4,    IPFIX_TYPE_UNSIGNED8,       1,  "protocolIdentifier",       1 }
#define sourceTransportPort         { 0,      7,    IPFIX_TYPE_UNSIGNED16,      2,  "sourceTransportPort",      1 }
#define sourceIPv4Address           { 0,      8,    IPFIX_TYPE_IPV4ADDRESS,     4,  "sourceIPv4Address",        1 }
#define ingressInterface            { 0,     10,    IPFIX_TYPE_UNSIGNED32,      4,  "ingressInterface",         0 }
#define destinationTransportPort    { 0,     11,    IPFIX_TYPE_UNSIGNED16,      2,  "destinationTransportPort", 1 }
#define destinationIPv4Address      { 0,     12,    IPFIX_TYPE_IPV4ADDRESS,     4,  "destinationIPv4Address",   1 }
#define egressInterface             { 0,     14,    IPFIX_TYPE_UNSIGNED32,      4,  "egressInterface",          0 }
#define flowStartMilliseconds       { 0,    152,    IPFIX_TYPE_TIME_MILLISEC,   8,  "flowStartMilliseconds",    1 }
#define flowEndMilliseconds         { 0,    153,    IPFIX_TYPE_TIME_MILLISEC,   8,  "flowEndMilliseconds",      1 }
#define selectorAlgorithm           { 0,    304,    IPFIX_TYPE_UNSIGNED16,      2,  "selectorAlgorithm",        0 }
#define samplingPacketInterval      { 0,    305,    IPFIX_TYPE_UNSIGNED32,      4,  "samplingPacketInterval",   0 }
#define rsHttpHostname              { 44913, 20,    IPFIX_TYPE_STRING,         32,  "rsHttpHostname",           0 }
#define rsHttpUrl                   { 44913, 21,    IPFIX_TYPE_STRING,         32,  "rsHttpUrl",                0 }

static struct ipfix_ie all_fields[] = {
    octetDeltaCount, packetDeltaCount, protocolIdentifier, sourceTransportPort, sourceIPv4Address, ingressInterface,
    destinationTransportPort, destinationIPv4Address, egressInterface, flowStartMilliseconds, flowEndMilliseconds,
    selectorAlgorithm, samplingPacketInterval, rsHttpHostname, rsHttpUrl
};

#define all_fields_count 15

#define DEFAULT_FPS 10000
#define DEFAULT_MAX_PACKETS 0
#define DEFAULT_ODID 44913

#define MAX_DATA_RECORDS 15
#define MAX_TEMPLATE_RECORDS 10
#define TEMPL_RESEND_PKTS 4096
#define TEMPL_RESEND_SEC 600

#endif /* IPFIXGENERATOR_CONFIG_H_ */
