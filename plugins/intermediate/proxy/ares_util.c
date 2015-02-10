/*
 * \file ares_util.c
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

#include "ares_util.h"
#include "proxy.h"

// Identifier for MSG_* macros
static char *msg_module = "ares_util";

/**
 * \brief Adds a name server to the list of specified name servers.
 *
 * \param[in] head Head of the name server list
 * \param[in] node Name server to be added to the list
 */
void ares_add_name_server (struct ares_addr_node **head, struct ares_addr_node *node) {
    struct ares_addr_node *last;
    node->next = NULL;
    if (*head) {
        last = *head;
        while (last->next) {
            last = last->next;
        }
        last->next = node;
    } else {
        *head = node;
    }
}

/**
 * \brief Destroys all c-ares name service channels in the provided pool.
 *
 * \param[in] pool c-ares name service pool (ares_channel[])
 */
void ares_destroy_all_channels (ares_channel *pool) {
    uint8_t i;
    for (i = 0; i < ARES_CHANNELS; ++i) {
        ares_destroy(pool[i]);
    }
}

/**
 * \brief Destroys the specified list of name servers.
 *
 * \param[in] head Head of the name server list
 */
void ares_destroy_name_server_list (struct ares_addr_node *head) {
    struct ares_addr_node *detached;
    while (head) {
        detached = head;
        head = head->next;
        free(detached);
    }
}

/**
 * \brief Waits for all domain name resolutions to be ready.
 *
 * \param[in] channel c-ares name service channel
 */
void ares_wait (ares_channel channel) {
    for (;;) {
        struct timeval *tvp, tv;
        fd_set read_fds, write_fds;
        int nfds;
 
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);

        if (nfds == 0) {
            break;
        }

        tvp = ares_timeout(channel, NULL, &tv);

        if (select(nfds, &read_fds, &write_fds, NULL, tvp) == -1) {
            MSG_ERROR(msg_module, "An error occurred while calling select()");
        }

        ares_process(channel, &read_fds, &write_fds);
    }
}

/**
 * \brief Waits for all c-ares name service channels to be ready.
 *
 * \param[in] pool c-ares name service pool (ares_channel[])
 */
void ares_wait_all_channels (ares_channel *pool) {
    uint8_t i;
    for (i = 0; i < ARES_CHANNELS; ++i) {
        ares_wait(pool[i]);
    }
}
