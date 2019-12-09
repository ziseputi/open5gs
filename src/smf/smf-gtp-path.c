/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "smf-context.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#include "smf-event.h"
#include "smf-gtp-path.h"
#include "smf-ipfw.h"

#define SMF_GTP_HANDLED     1

static int smf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf);
static int smf_gtp_send_to_bearer(smf_bearer_t *bearer, ogs_pkbuf_t *sendbuf);

static void _gtpv1_tun_recv_cb(short when, ogs_socket_t fd, void *data)
{
    ogs_pkbuf_t *recvbuf = NULL;
    int n;
    int rv;
    smf_bearer_t *bearer = NULL;

    recvbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_reserve(recvbuf, OGS_GTPV1U_HEADER_LEN);
    ogs_pkbuf_put(recvbuf, OGS_MAX_SDU_LEN-OGS_GTPV1U_HEADER_LEN);

    n = ogs_read(fd, recvbuf->data, recvbuf->len);
    if (n <= 0) {
        ogs_log_message(OGS_LOG_WARN, ogs_socket_errno, "ogs_read() failed");
        ogs_pkbuf_free(recvbuf);
        return;
    }

    ogs_pkbuf_trim(recvbuf, n);

    /* Find the bearer by packet filter */
    bearer = smf_bearer_find_by_packet(recvbuf);
    if (bearer) {
        /* Unicast */
        rv = smf_gtp_send_to_bearer(bearer, recvbuf);
        ogs_assert(rv == OGS_OK);
    } else {
        if (ogs_config()->parameter.multicast) {
            rv = smf_gtp_handle_multicast(recvbuf);
            ogs_assert(rv != OGS_ERROR);
        }
    }

    ogs_pkbuf_free(recvbuf);
}

static void _gtpv2_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    smf_event_t *e = NULL;
    int rv;
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_gtp_node_t *gnode = NULL;

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recvfrom() failed");
        ogs_pkbuf_free(pkbuf);
        return;
    }

    ogs_pkbuf_trim(pkbuf, size);

    e = smf_event_new(SMF_EVT_S5C_MESSAGE);
    gnode = ogs_gtp_node_find_by_addr(&smf_self()->sgw_s5c_list, &from);
    if (!gnode) {
        gnode = ogs_gtp_node_add_by_addr(&smf_self()->sgw_s5c_list, &from);
        ogs_assert(gnode);
        gnode->sock = data;
    }
    ogs_assert(e);
    e->gnode = gnode;
    e->gtpbuf = pkbuf;

    rv = ogs_queue_push(smf_self()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_pkbuf_free(e->gtpbuf);
        smf_event_free(e);
    }
}

int smf_gtp_open(void)
{
    smf_dev_t *dev = NULL;
    smf_subnet_t *subnet = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    int rc;

    ogs_list_for_each(&smf_self()->gtpc_list, node) {
        sock = ogs_gtp_server(node);
        ogs_assert(sock);
        
        node->poll = ogs_pollset_add(smf_self()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
    }
    ogs_list_for_each(&smf_self()->gtpc_list6, node) {
        sock = ogs_gtp_server(node);
        ogs_assert(sock);

        node->poll = ogs_pollset_add(smf_self()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
    }

    smf_self()->gtpc_sock = ogs_socknode_sock_first(&smf_self()->gtpc_list);
    if (smf_self()->gtpc_sock)
        smf_self()->gtpc_addr = &smf_self()->gtpc_sock->local_addr;

    smf_self()->gtpc_sock6 = ogs_socknode_sock_first(&smf_self()->gtpc_list6);
    if (smf_self()->gtpc_sock6)
        smf_self()->gtpc_addr6 = &smf_self()->gtpc_sock6->local_addr;

    ogs_assert(smf_self()->gtpc_addr || smf_self()->gtpc_addr6);

    /* NOTE : tun device can be created via following command.
     *
     * $ sudo ip tuntap add name ogstun mode tun
     *
     * Also, before running smf, assign the one IP from IP pool of UE 
     * to ogstun. The IP should not be assigned to UE
     *
     * $ sudo ifconfig ogstun 45.45.0.1/16 up
     *
     */

    /* Open Tun interface */
    for (dev = smf_dev_first(); dev; dev = smf_dev_next(dev)) {
        dev->fd = ogs_tun_open(dev->ifname, IFNAMSIZ, 0);
        if (dev->fd == INVALID_SOCKET) {
            ogs_error("tun_open(dev:%s) failed", dev->ifname);
            return OGS_ERROR;
        }

        dev->poll = ogs_pollset_add(smf_self()->pollset,
                OGS_POLLIN, dev->fd, _gtpv1_tun_recv_cb, NULL);
        ogs_assert(dev->poll);
    }

    /* 
     * On Linux, it is possible to create a persistent tun/tap 
     * interface which will continue to exist even if open5gs quit, 
     * although this is normally not required. 
     * It can be useful to set up a tun/tap interface owned 
     * by a non-root user, so open5gs can be started without 
     * needing any root privileges at all.
     */

    /* Set P-to-P IP address with Netmask
     * Note that Linux will skip this configuration */
    for (subnet = smf_subnet_first(); 
            subnet; subnet = smf_subnet_next(subnet)) {
        ogs_assert(subnet->dev);
        rc = ogs_tun_set_ip(subnet->dev->ifname, &subnet->gw, &subnet->sub);
        if (rc != OGS_OK) {
            ogs_error("ogs_tun_set_ip(dev:%s) failed", subnet->dev->ifname);
            return OGS_ERROR;
        }
    }

    /* Link-Local Address for SMF_TUN */
    for (dev = smf_dev_first(); dev; dev = smf_dev_next(dev))
        dev->link_local_addr = ogs_link_local_addr_by_dev(dev->ifname);

    return OGS_OK;
}

void smf_gtp_close(void)
{
    smf_dev_t *dev = NULL;

    ogs_socknode_remove_all(&smf_self()->gtpc_list);
    ogs_socknode_remove_all(&smf_self()->gtpc_list6);

    for (dev = smf_dev_first(); dev; dev = smf_dev_next(dev)) {
        ogs_pollset_remove(dev->poll);
        ogs_closesocket(dev->fd);
    }
}

static int smf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf)
{
    int rv;
    struct ip *ip_h =  NULL;
    struct ip6_hdr *ip6_h =  NULL;

    ip_h = (struct ip *)recvbuf->data;
    if (ip_h->ip_v == 6) {
#if COMPILE_ERROR_IN_MAC_OS_X  /* Compiler error in Mac OS X platform */
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        if (IN6_IS_ADDR_MULTICAST(&ip6_h->ip6_dst))
#else
        struct in6_addr ip6_dst;
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        memcpy(&ip6_dst, &ip6_h->ip6_dst, sizeof(struct in6_addr));
        if (IN6_IS_ADDR_MULTICAST(&ip6_dst))
#endif
        {
            smf_sess_t *sess = NULL;

            /* IPv6 Multicast */
            ogs_list_for_each(&smf_self()->sess_list, sess) {
                if (sess->ipv6) {
                    /* PDN IPv6 is avaiable */
                    smf_bearer_t *bearer = smf_default_bearer_in_sess(sess);
                    ogs_assert(bearer);

                    rv = smf_gtp_send_to_bearer(bearer, recvbuf);
                    ogs_assert(rv == OGS_OK);

                    return SMF_GTP_HANDLED;
                }
            }
        }
    }

    return OGS_OK;
}

static int smf_gtp_send_to_bearer(smf_bearer_t *bearer, ogs_pkbuf_t *sendbuf)
{
    char buf[OGS_ADDRSTRLEN];
    int rv;
    ogs_gtp_header_t *gtp_h = NULL;

    ogs_assert(bearer);
    ogs_assert(bearer->gnode);
    ogs_assert(bearer->gnode->sock);

    /* Add GTP-U header */
    ogs_assert(ogs_pkbuf_push(sendbuf, OGS_GTPV1U_HEADER_LEN));
    gtp_h = (ogs_gtp_header_t *)sendbuf->data;
    /* Bits    8  7  6  5  4  3  2  1
     *        +--+--+--+--+--+--+--+--+
     *        |version |PT| 1| E| S|PN|
     *        +--+--+--+--+--+--+--+--+
     *         0  0  1   1  0  0  0  0
     */
    gtp_h->flags = 0x30;
    gtp_h->type = OGS_GTPU_MSGTYPE_GPDU;
    gtp_h->length = htons(sendbuf->len - OGS_GTPV1U_HEADER_LEN);
    gtp_h->teid = htonl(bearer->sgw_s5u_teid);

    /* Send to SGW */
    ogs_debug("[SMF] SEND GPU-U to SGW[%s] : TEID[0x%x]",
        OGS_ADDR(&bearer->gnode->remote_addr, buf),
        bearer->sgw_s5u_teid);
    rv =  ogs_gtp_sendto(bearer->gnode, sendbuf);

    return rv;
}
