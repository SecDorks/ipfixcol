/*
 * \file ipfixgenerator.h
 * \author Kirc <kirc&secdorks.net>
 * \brief IPFIXcol 'IPFIX generator' input plugin.
 *
 * IPFIXcol input plugin for generating semi-random IPFIX traffic. The main
 * purpose of this plugin is performance testing.
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

#ifndef IPFIXGENERATOR_H_
#define IPFIXGENERATOR_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libxml/parser.h>

#include <ipfixcol.h>

#define IPFIX_MSG_MAX_LENGTH 1500
#define IPFIX_RECORD_HEADER_LENGTH 4 // Define in upstream?

struct ipfixgenerator_config {
    time_t last_templates_transmission;
    uint32_t max_packets;
    uint32_t max_records;
    uint64_t packets_sent;
    uint64_t data_records_sent;

    struct input_info_file *info;
    uint8_t templ_sets_count;
    struct ipfix_template_set *templ_set[MSG_MAX_TEMPL_SETS];

    /* Speed control */
    time_t last_speed_check;
    uint32_t sleep_time_usec;
    uint32_t target_fps;
    uint64_t last_data_records_sent;
};

typedef enum {
    IPFIX_TYPE_UNSIGNED8,
    IPFIX_TYPE_UNSIGNED16,
    IPFIX_TYPE_UNSIGNED32,
    IPFIX_TYPE_UNSIGNED64,
    IPFIX_TYPE_IPV4ADDRESS,
    IPFIX_TYPE_IPV6ADDRESS,
    IPFIX_TYPE_STRING,
    IPFIX_TYPE_TIME_MILLISEC
} ipfix_type_t;

struct ipfix_ie {
    uint32_t eid;
    uint16_t id;
    ipfix_type_t type;
    uint16_t length;
    char *name;
    uint8_t mandatory;
};

#endif /* IPFIXGENERATOR_H_ */
