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

#define OGS_PFCP_NODE_ID_HDR_LEN    1
#define OGS_PFCP_NODE_ID_IPV4_LEN   (OGS_IPV4_LEN + OGS_PFCP_NODE_ID_HDR_LEN)
#define OGS_PFCP_NODE_ID_IPV6_LEN   (OGS_IPV6_LEN + OGS_PFCP_NODE_ID_HDR_LEN)

int ogs_pfcp_sockaddr_to_node_id(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6, int prefer_ipv4,
    ogs_pfcp_node_id_t *node_id, int *len)
{
    int rv;
    char hostname[OGS_MAX_FQDN_LEN];

    ogs_assert(node_id);

    memset(node_id, 0, sizeof *node_id);

    if (addr && addr->hostname) {
        rv = ogs_getnameinfo(hostname, OGS_MAX_FQDN_LEN, addr, 0);
        if (rv == OGS_OK && strcmp(addr->hostname, hostname) == 0) {
            node_id->type = OGS_PFCP_NODE_ID_FQDN;
            *len = OGS_PFCP_NODE_ID_HDR_LEN +
                        ogs_fqdn_build(node_id->fqdn,
                            addr->hostname, strlen(addr->hostname));

            return OGS_OK;
        }
    }

    if (addr6 && addr6->hostname) {
        rv = ogs_getnameinfo(hostname, OGS_MAX_FQDN_LEN, addr6, 0);
        if (rv == OGS_OK && strcmp(addr6->hostname, hostname) == 0) {
            node_id->type = OGS_PFCP_NODE_ID_FQDN;
            *len = OGS_PFCP_NODE_ID_HDR_LEN +
                        ogs_fqdn_build(node_id->fqdn,
                            addr6->hostname, strlen(addr6->hostname));

            return OGS_OK;
        }
    }

    if (prefer_ipv4 && addr) {
        node_id->type = OGS_PFCP_NODE_ID_IPV4;
        node_id->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_PFCP_NODE_ID_IPV4_LEN;
    } else if (addr6) {
        node_id->type = OGS_PFCP_NODE_ID_IPV6;
        memcpy(node_id->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_PFCP_NODE_ID_IPV6_LEN;
    } else if (addr) {
        node_id->type = OGS_PFCP_NODE_ID_IPV4;
        node_id->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_PFCP_NODE_ID_IPV4_LEN;
    } else {
        ogs_assert_if_reached();
        return OGS_ERROR;
    }

    return OGS_OK;
}

#define OGS_PFCP_F_SEID_HDR_LEN     9
#define OGS_PFCP_F_SEID_IPV4_LEN    (OGS_IPV4_LEN + OGS_PFCP_F_SEID_HDR_LEN)
#define OGS_PFCP_F_SEID_IPV6_LEN    (OGS_IPV6_LEN + OGS_PFCP_F_SEID_HDR_LEN)
#define OGS_PFCP_F_SEID_IPV4V6_LEN  (OGS_IPV4V6_LEN + OGS_PFCP_F_SEID_HDR_LEN)

int ogs_pfcp_f_seid_to_sockaddr(
    ogs_pfcp_f_seid_t *f_seid, uint16_t port, ogs_sockaddr_t **list)
{
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(f_seid);
    ogs_assert(list);

    addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    ogs_assert(addr);
    addr->ogs_sa_family = AF_INET;
    addr->ogs_sin_port = htobe16(port);

    addr6 = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    ogs_assert(addr6);
    addr6->ogs_sa_family = AF_INET6;
    addr6->ogs_sin_port = htobe16(port);

    if (f_seid->ipv4 && f_seid->ipv6) {
        addr->next = addr6;

        addr->sin.sin_addr.s_addr = f_seid->both.addr;
        memcpy(addr6->sin6.sin6_addr.s6_addr, f_seid->both.addr6, OGS_IPV6_LEN);

        *list = addr;
    } else if (f_seid->ipv4) {
        addr->sin.sin_addr.s_addr = f_seid->addr;
        ogs_free(addr6);

        *list = addr;
    } else if (f_seid->ipv6) {
        memcpy(addr6->sin6.sin6_addr.s6_addr, f_seid->addr6, OGS_IPV6_LEN);
        ogs_free(addr);

        *list = addr6;
    } else {
        ogs_free(addr);
        ogs_free(addr6);
        ogs_assert_if_reached();
    }

    return OGS_OK;
}

int ogs_pfcp_sockaddr_to_f_seid(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6,
    ogs_pfcp_f_seid_t *f_seid, int *len)
{
    ogs_assert(f_seid);

    memset(f_seid, 0, sizeof *f_seid);

    if (addr && addr6) {
        f_seid->ipv4 = 1;
        f_seid->both.addr = addr->sin.sin_addr.s_addr;
        f_seid->ipv6 = 1;
        memcpy(f_seid->both.addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_PFCP_F_SEID_IPV4V6_LEN;
    } else if (addr) {
        f_seid->ipv4 = 1;
        f_seid->ipv6 = 0;
        f_seid->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_PFCP_F_SEID_IPV4_LEN;
    } else if (addr6) {
        f_seid->ipv4 = 0;
        f_seid->ipv6 = 1;
        memcpy(f_seid->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_PFCP_F_SEID_IPV6_LEN;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

int ogs_pfcp_f_seid_to_ip(ogs_pfcp_f_seid_t *f_seid, ogs_ip_t *ip)
{
    ogs_assert(ip);
    ogs_assert(f_seid);

    memset(ip, 0, sizeof *ip);

    ip->ipv4 = f_seid->ipv4;
    ip->ipv6 = f_seid->ipv6;

    if (ip->ipv4 && ip->ipv6) {
        ip->both.addr = f_seid->both.addr;
        memcpy(ip->both.addr6, f_seid->both.addr6, OGS_IPV6_LEN);
        ip->len = OGS_IPV4V6_LEN;
    } else if (ip->ipv4) {
        ip->addr = f_seid->addr;
        ip->len = OGS_IPV4_LEN;
    } else if (ip->ipv6) {
        memcpy(ip->addr6, f_seid->addr6, OGS_IPV6_LEN);
        ip->len = OGS_IPV6_LEN;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

#define OGS_PFCP_F_TEID_HDR_LEN     5
#define OGS_PFCP_F_TEID_IPV4_LEN    (OGS_IPV4_LEN + OGS_PFCP_F_TEID_HDR_LEN)
#define OGS_PFCP_F_TEID_IPV6_LEN    (OGS_IPV6_LEN + OGS_PFCP_F_TEID_HDR_LEN)
#define OGS_PFCP_F_TEID_IPV4V6_LEN  (OGS_IPV4V6_LEN + OGS_PFCP_F_TEID_HDR_LEN)

static int sockaddr_to_f_teid(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6,
    ogs_pfcp_f_teid_t *f_teid, int *len)
{
    ogs_assert(addr == NULL || addr6 == NULL);
    ogs_assert(f_teid);
    memset(f_teid, 0, sizeof *f_teid);

    if (addr && addr6) {
        f_teid->ipv4 = 1;
        f_teid->both.addr = addr->sin.sin_addr.s_addr;
        f_teid->ipv6 = 1;
        memcpy(f_teid->both.addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_PFCP_F_TEID_IPV4V6_LEN;
    } else if (addr) {
        f_teid->ipv4 = 1;
        f_teid->ipv6 = 0;
        f_teid->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_PFCP_F_TEID_IPV4_LEN;
    } else if (addr6) {
        f_teid->ipv4 = 0;
        f_teid->ipv6 = 1;
        memcpy(f_teid->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_PFCP_F_TEID_IPV6_LEN;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

int ogs_pfcp_sockaddr_to_f_teid(
    ogs_sockaddr_t *a, ogs_sockaddr_t *b,
    ogs_pfcp_f_teid_t *f_teid, int *len)
{
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    if (a && a->sin.sin_family == AF_INET) {
        addr = a;
    }
    if (a && a->sin.sin_family == AF_INET6) {
        addr6 = a;
    }
    if (b && b->sin.sin_family == AF_INET) {
        ogs_assert(addr);
        addr = b;
    }
    if (b && b->sin.sin_family == AF_INET6) {
        ogs_assert(addr6);
        addr6 = b;
    }

    return sockaddr_to_f_teid(addr, addr6, f_teid, len);
}

int ogs_pfcp_outer_hdr_to_ip(ogs_pfcp_outer_hdr_t *outer_hdr, ogs_ip_t *ip)
{
    ogs_assert(ip);
    ogs_assert(outer_hdr);

    memset(ip, 0, sizeof *ip);

    ip->ipv4 = outer_hdr->gtpu_ipv4;
    ip->ipv6 = outer_hdr->gtpu_ipv6;

    if (ip->ipv4 && ip->ipv6) {
        ip->both.addr = outer_hdr->both.addr;
        memcpy(ip->both.addr6, outer_hdr->both.addr6, OGS_IPV6_LEN);
        ip->len = OGS_IPV4V6_LEN;
    } else if (ip->ipv4) {
        ip->addr = outer_hdr->addr;
        ip->len = OGS_IPV4_LEN;
    } else if (ip->ipv6) {
        memcpy(ip->addr6, outer_hdr->addr6, OGS_IPV6_LEN);
        ip->len = OGS_IPV6_LEN;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

OGS_STATIC_ASSERT(OGS_MAX_NUM_OF_PDR > 3);
void ogs_pfcp_create_pdrs_in_session_establishment(
    ogs_pfcp_tlv_create_pdr_t *create_pdrs[][OGS_MAX_NUM_OF_PDR],
    ogs_pfcp_session_establishment_request_t *req)
{
    ogs_assert(create_pdrs);
    ogs_assert(req);

    (*create_pdrs)[0] = &req->create_pdr0;
    (*create_pdrs)[1] = &req->create_pdr1;
    (*create_pdrs)[2] = &req->create_pdr2;
    (*create_pdrs)[3] = &req->create_pdr3;
}

OGS_STATIC_ASSERT(OGS_MAX_NUM_OF_FAR > 3);
void ogs_pfcp_create_fars_in_session_establishment(
    ogs_pfcp_tlv_create_far_t *create_fars[][OGS_MAX_NUM_OF_FAR],
    ogs_pfcp_session_establishment_request_t *req)
{
    ogs_assert(create_fars);
    ogs_assert(req);

    (*create_fars)[0] = &req->create_far0;
    (*create_fars)[1] = &req->create_far1;
    (*create_fars)[2] = &req->create_far2;
    (*create_fars)[3] = &req->create_far3;
}

OGS_STATIC_ASSERT(OGS_MAX_NUM_OF_URR > 1);
void ogs_pfcp_create_urrs_in_session_establishment(
    ogs_pfcp_tlv_create_urr_t *create_urrs[][OGS_MAX_NUM_OF_URR],
    ogs_pfcp_session_establishment_request_t *req)
{
    ogs_assert(create_urrs);
    ogs_assert(req);

    (*create_urrs)[0] = &req->create_urr0;
    (*create_urrs)[1] = &req->create_urr1;
}

OGS_STATIC_ASSERT(OGS_MAX_NUM_OF_QER > 1);
void ogs_pfcp_create_qers_in_session_establishment(
    ogs_pfcp_tlv_create_qer_t *create_qers[][OGS_MAX_NUM_OF_QER],
    ogs_pfcp_session_establishment_request_t *req)
{
    ogs_assert(create_qers);
    ogs_assert(req);

    (*create_qers)[0] = &req->create_qer0;
    (*create_qers)[1] = &req->create_qer1;
}
