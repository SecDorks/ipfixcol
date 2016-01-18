/*
 * \file timestampfieldmerge.c
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
 */

#include "timestampfieldmerge.h"

/* API version constant */
IPFIXCOL_API_VERSION;

/**
 *  \brief Initialize intermediate plugin
 *
 * \param[in] params configuration xml for the plugin
 * \param[in] ip_config configuration structure of corresponding intermediate process
 * \param[in] ip_id source ID into template manager for creating templates
 * \param[in] template_mgr collector's Template Manager
 * \param[out] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_init(char *params, void *ip_config, uint32_t ip_id, struct ipfix_template_mgr *template_mgr, void **config)
{
    // struct httpfieldmerge_config *conf;

    // conf = (struct httpfieldmerge_config *) calloc(1, sizeof(*conf));
    // if (!conf) {
    //     MSG_ERROR(msg_module, "Memory allocation failed (%s:%d)", __FILE__, __LINE__);
    //     return -1;
    // }

    // conf->params = params;
    // conf->ip_config = ip_config;
    // conf->ip_id = ip_id;
    // conf->tm = template_mgr;

    // /* Initialize (empty) hashmaps */
    // conf->templ_stats = NULL;
    // conf->od_stats = NULL;
    // conf->od_stats_key_len = offsetof(struct od_stats_elem_t, ip_id)
    //         + sizeof(uint32_t) /* Last key component, ip_id, is if type 'uint32_t' */
    //         - offsetof(struct od_stats_elem_t, od_id);

    // *config = conf;

    MSG_INFO(msg_module, "Plugin initialization completed successfully");

    /* Plugin successfully initialized */
    return 0;
}

/**
 *  \brief Initialize intermediate Plugin
 *
 * \param[in] params configuration xml for the plugin
 * \param[in] ip_config configuration structure of corresponding intermediate process
 * \param[in] ip_id source ID into template manager for creating templates
 * \param[in] template_mgr collector's Template Manager
 * \param[out] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_process_message(void *config, void *message)
{
    drop_message(conf->ip_config, message);
    pass_message(conf->ip_config, (void *) new_msg);
    return 0;
}

/**
 * \brief Close intermediate Plugin
 *
 * \param[in] config configuration structure
 * \return 0 on success, negative value otherwise
 */
int intermediate_close(void *config)
{
    return 0;
}
