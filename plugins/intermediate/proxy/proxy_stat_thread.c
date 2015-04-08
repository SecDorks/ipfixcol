/*
 * \file proxy_stat_thread.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "queues.h"
#include "proxy_stat_thread.h"
#include "proxy.h"

// Identifier for MSG_* macros
static char *msg_module = "proxy_stat_thread";

/**
 * \brief Dummy SIGUSR1 signal handler
 */
void term_signal_handler (int sig) {
    (void) sig;
}

/**
 * \brief Main routine of statistics thread
 *
 * \param[in] config configuration structure for thread
 * \return NULL once thread shutdown is signaled by proxy plugin
 */
void *stat_thread (void* config) {
    struct proxy_config *conf = (struct proxy_config *) config;
    struct sigaction action;

    // Catch SIGUSR1
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = term_signal_handler;
    sigaction(SIGUSR1, &action, NULL);

    // Set thread name
    prctl(PR_SET_NAME, "med:proxy:stats", 0, 0, 0);

    while (conf->stat_interval) {
        sleep(conf->stat_interval);

        // Check whether thread should be killed (by proxy plugin)
        if (conf->stat_done) {
            break;
        }

        MSG_INFO(msg_module, "");
        MSG_INFO(msg_module, "Records with domain resolution: %u; records without domain resolution: %u", conf->records_resolution, conf->records_wo_resolution);
        MSG_INFO(msg_module, "Failed resolutions: %u; skipped resolutions: %u", conf->failed_resolutions, conf->skipped_resolutions);
        MSG_INFO(msg_module, "");
    }

    return NULL;
}
