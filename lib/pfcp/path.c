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

#include "ogs-pfcp.h"

ogs_sock_t *ogs_pfcp_server(ogs_socknode_t *node)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_sock_t *pfcp;
    ogs_assert(node);

    pfcp = ogs_udp_server(node);
    ogs_assert(pfcp);

    ogs_info("pfcp_server() [%s]:%d",
            OGS_ADDR(node->addr, buf), OGS_PORT(node->addr));

    return pfcp;
}

int ogs_pfcp_connect(ogs_sock_t *ipv4, ogs_sock_t *ipv6, ogs_pfcp_node_t *pnode)
{
    ogs_sockaddr_t *addr;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(ipv4 || ipv6);
    ogs_assert(pnode);
    ogs_assert(pnode->sa_list);

    addr = pnode->sa_list;
    while (addr) {
        ogs_sock_t *sock = NULL;

        if (addr->ogs_sa_family == AF_INET)
            sock = ipv4;
        else if (addr->ogs_sa_family == AF_INET6)
            sock = ipv6;
        else
            ogs_assert_if_reached();

        if (sock) {
            ogs_info("ogs_pfcp_connect() [%s]:%d",
                    OGS_ADDR(addr, buf), OGS_PORT(addr));

            pnode->sock = sock;
            memcpy(&pnode->addr, addr, sizeof pnode->addr);
            break;
        }

        addr = addr->next;
    }

    if (addr == NULL) {
        ogs_error("ogs_pfcp_connect() [%s]:%d failed",
                OGS_ADDR(pnode->sa_list, buf), OGS_PORT(pnode->sa_list));
        ogs_error("Please check the IP version between SMF and UPF nodes.");
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_pfcp_send(ogs_pfcp_node_t *pnode, ogs_pkbuf_t *pkbuf)
{
    ssize_t sent;
    ogs_sock_t *sock = NULL;

    ogs_assert(pnode);
    ogs_assert(pkbuf);
    sock = pnode->sock;
    ogs_assert(sock);

    sent = ogs_send(sock->fd, pkbuf->data, pkbuf->len, 0);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("ogs_send() failed");
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_pfcp_sendto(ogs_pfcp_node_t *pnode, ogs_pkbuf_t *pkbuf)
{
    ssize_t sent;
    ogs_sock_t *sock = NULL;
    ogs_sockaddr_t *addr = NULL;

    ogs_assert(pnode);
    ogs_assert(pkbuf);
    sock = pnode->sock;
    ogs_assert(sock);
    addr = &pnode->addr;
    ogs_assert(addr);

    sent = ogs_sendto(sock->fd, pkbuf->data, pkbuf->len, 0, addr);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("ogs_sendto() failed");
        return OGS_ERROR;
    }

    return OGS_OK;
}

void ogs_pfcp_send_heartbeat_response(ogs_pfcp_xact_t *xact)
{
    int rv;
    ogs_pkbuf_t *n4buf = NULL;
    ogs_pfcp_header_t h;

    ogs_assert(xact);

    memset(&h, 0, sizeof(ogs_pfcp_header_t));
    h.type = OGS_PFCP_HEARTBEAT_RESPONSE_TYPE;
    h.seid = 0;

    n4buf = ogs_pfcp_n4_build_heartbeat_response(h.type);
    ogs_expect_or_return(n4buf);

    rv = ogs_pfcp_xact_update_tx(xact, &h, n4buf);
    ogs_expect_or_return(rv == OGS_OK);

    rv = ogs_pfcp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
}

