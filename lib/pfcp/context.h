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

#if !defined(OGS_PFCP_INSIDE) && !defined(OGS_PFCP_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_PFCP_CONTEXT_H
#define OGS_PFCP_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_MAX_NUM_OF_PDR      4
#define OGS_MAX_NUM_OF_FAR      1
#define OGS_MAX_NUM_OF_URR      1
#define OGS_MAX_NUM_OF_QER      1

typedef struct ogs_pfcp_context_s {
    uint32_t        pfcp_port;      /* PFCP local port */

    ogs_list_t      pfcp_list;      /* PFCP IPv4 Server List */
    ogs_list_t      pfcp_list6;     /* PFCP IPv6 Server List */
    ogs_sock_t      *pfcp_sock;     /* PFCP IPv4 Socket */
    ogs_sock_t      *pfcp_sock6;    /* PFCP IPv6 Socket */
    ogs_sockaddr_t  *pfcp_addr;     /* PFCP IPv4 Address */
    ogs_sockaddr_t  *pfcp_addr6;    /* PFCP IPv6 Address */

    uint32_t        pfcp_started;   /* UTC time when the PFCP entity started */
    uint8_t         function_features; /* Function Features */

    ogs_list_t      n4_list;        /* PFCP Node List */
    ogs_pfcp_node_t *peer;          /* Iterator for Peer round-robin */

    ogs_list_t      sess_list;
} ogs_pfcp_context_t;

typedef struct ogs_pfcp_sess_s {
    uint64_t        local_n4_seid;  /* Local SEID is dervied from INDEX */
    uint64_t        remote_n4_seid; /* Remote SEID is received from Peer */

    uint8_t         pdr_id;     /* ID Generator(1~MAX_NUM_OF_PDR) */
    ogs_list_t      pdr_list;   /* PDR List */

    uint8_t         far_id;     /* ID Generator(1~MAX_NUM_OF_FAR) */
    ogs_list_t      far_list;   /* FAR List */

    uint8_t         urr_id;     /* ID Generator(1~MAX_NUM_OF_URR) */
    ogs_list_t      urr_list;   /* URR List */

    uint8_t         qer_id;     /* ID Generator(1~MAX_NUM_OF_URR) */
    ogs_list_t      qer_list;   /* QER List */

    /* Related Context */
    ogs_pfcp_node_t *node;
} ogs_pfcp_sess_t;

typedef struct ogs_pfcp_far_s ogs_pfcp_far_t;
typedef struct ogs_pfcp_urr_s ogs_pfcp_urr_t;
typedef struct ogs_pfcp_qer_s ogs_pfcp_qer_t;

typedef struct ogs_pfcp_pdr_s {
    ogs_lnode_t     lnode;

    uint16_t        id;

    ogs_pfcp_far_t  *far;
    ogs_pfcp_urr_t  *urr;
    ogs_pfcp_qer_t  *qer;

    ogs_pfcp_sess_t *sess;
} ogs_pfcp_pdr_t;

typedef struct ogs_pfcp_far_s {
    ogs_lnode_t     lnode;

    uint16_t        id;

    ogs_pfcp_pdr_t  *pdr;
    ogs_pfcp_sess_t *sess;
} ogs_pfcp_far_t;

typedef struct ogs_pfcp_urr_s {
    ogs_lnode_t     lnode;

    uint16_t        id;

    ogs_pfcp_pdr_t  *pdr;
    ogs_pfcp_sess_t *sess;
} ogs_pfcp_urr_t;

typedef struct ogs_pfcp_qer_s {
    ogs_lnode_t     lnode;

    uint16_t        id;

    ogs_pfcp_pdr_t  *pdr;
    ogs_pfcp_sess_t *sess;
} ogs_pfcp_qer_t;

void ogs_pfcp_context_init(void);
void ogs_pfcp_context_final(void);
ogs_pfcp_context_t *ogs_pfcp_self(void);
int ogs_pfcp_context_parse_config(const char *local, const char *remote);

ogs_pfcp_pdr_t *ogs_pfcp_pdr_add(ogs_pfcp_sess_t *sess);
void ogs_pfcp_pdr_remove(ogs_pfcp_pdr_t *pdr);
void ogs_pfcp_pdr_remove_all(ogs_pfcp_sess_t *sess);
ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_by_id(ogs_pfcp_sess_t *sess, uint8_t id);

ogs_pfcp_far_t *ogs_pfcp_far_add(ogs_pfcp_sess_t *sess);
void ogs_pfcp_far_remove(ogs_pfcp_far_t *far);
void ogs_pfcp_far_remove_all(ogs_pfcp_sess_t *sess);
ogs_pfcp_far_t *ogs_pfcp_far_find_by_id(ogs_pfcp_sess_t *sess, uint8_t id);

#ifdef __cplusplus
}
#endif

#endif /* OGS_PFCP_CONTEXT_H */
