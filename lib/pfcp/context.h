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

typedef struct ogs_pfcp_context_s {
    uint32_t        pfcp_port;      /* PFCP local port */

    ogs_list_t      pfcp_list;      /* PFCP IPv4 Server List */
    ogs_list_t      pfcp_list6;     /* PFCP IPv6 Server List */
    ogs_sock_t      *pfcp_sock;     /* PFCP IPv4 Socket */
    ogs_sock_t      *pfcp_sock6;    /* PFCP IPv6 Socket */
    ogs_sockaddr_t  *pfcp_addr;     /* PFCP IPv4 Address */
    ogs_sockaddr_t  *pfcp_addr6;    /* PFCP IPv6 Address */

    uint32_t        pfcp_started;   /* UTC time when the PFCP entity started */

    ogs_list_t      n4_list;        /* PFCP Node List */
    ogs_pfcp_node_t *peer;          /* Iterator for Peer round-robin */

    ogs_list_t      sess_list;
} ogs_pfcp_context_t;

typedef struct ogs_pfcp_far_s ogs_pfcp_far_t;
typedef struct ogs_pfcp_urr_s ogs_pfcp_urr_t;
typedef struct ogs_pfcp_qer_s ogs_pfcp_qer_t;
typedef struct ogs_pfcp_bar_s ogs_pfcp_bar_t;

typedef uint16_t ogs_pfcp_pdr_id_t;
typedef uint32_t ogs_pfcp_far_id_t;
typedef uint32_t ogs_pfcp_urr_id_t;
typedef uint32_t ogs_pfcp_qer_id_t;
typedef uint8_t  ogs_pfcp_bar_id_t;

typedef uint32_t ogs_pfcp_precedence_t;
typedef uint8_t  ogs_pfcp_interface_t;
typedef uint8_t  ogs_pfcp_apply_action_t;

typedef struct ogs_pfcp_sess_s {
    uint64_t        local_n4_seid;  /* Local SEID is dervied from INDEX */
    uint64_t        remote_n4_seid; /* Remote SEID is received from Peer */

    ogs_pfcp_pdr_id_t   pdr_id;     /* ID Generator(1~MAX_NUM_OF_PDR) */
    ogs_list_t          pdr_list;   /* PDR List */

    ogs_pfcp_far_id_t   far_id;     /* ID Generator(1~MAX_NUM_OF_FAR) */
    ogs_list_t          far_list;   /* FAR List */

    ogs_pfcp_urr_id_t   urr_id;     /* ID Generator(1~MAX_NUM_OF_URR) */
    ogs_list_t          urr_list;   /* URR List */

    ogs_pfcp_qer_id_t   qer_id;     /* ID Generator(1~MAX_NUM_OF_URR) */
    ogs_list_t          qer_list;   /* QER List */

    ogs_pfcp_bar_id_t   bar_id;     /* ID Generator(1~MAX_NUM_OF_BAR) */
    ogs_pfcp_bar_t      *bar;       /* BAR Item */

    /* Related Context */
    ogs_pfcp_node_t *node;
} ogs_pfcp_sess_t;

typedef struct ogs_pfcp_pdr_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_pdr_id_t       id;
/*
 * 8.2.11 Precedence
 *
 * The Precedence value shall be encoded as an Unsigned32 binary integer value. The lower precedence values
 * indicate higher precedence of the PDR, and the higher precedence values
 * indicate lower precedence of the PDR when matching a packet.
 */
    ogs_pfcp_precedence_t   precedence;
/*
 * 8.2.2 Source Interface
 *
 * NOTE 1: The "Access" and "Core" values denote an uplink and downlink
 * traffic direction respectively.
 * NOTE 2: For indirect data forwarding, the Source Interface in the PDR and
 * the Destination Interface in the FAR shall both be set to "Access",
 * in the forwarding SGW(s). The Interface value does not infer any
 * traffic direction, in PDRs and FARs set up for indirect data
 * forwarding, i.e. with both the Source and Destination Interfaces set
 * to Access.
 */
    ogs_pfcp_interface_t    src_if;

    ogs_pfcp_far_t          *far;
    int                     num_of_urr;
    ogs_pfcp_urr_t          *urrs[OGS_MAX_NUM_OF_URR];
    int                     num_of_qer;
    ogs_pfcp_qer_t          *qers[OGS_MAX_NUM_OF_QER];

    ogs_pfcp_sess_t         *sess;
} ogs_pfcp_pdr_t;

typedef struct ogs_pfcp_far_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_far_id_t       id;

/*
 * 8.2.26 Apply Action
 *
 * Bit 1 – DROP (Drop): when set to 1, this indicates a request
 * to drop the packets.
 * Bit 2 – FORW (Forward): when set to 1, this indicates a request
 * to forward the packets.
 * Bit 3 – BUFF (Buffer): when set to 1, this indicates a request
 * to buffer the packets.
 * Bit 4 – NOCP (Notify the CP function): when set to 1,
 * this indicates a request to notify the CP function about the
 * arrival of a first downlink packet being buffered.
 * Bit 5 – DUPL (Duplicate): when set to 1, this indicates a request
 * to duplicate the packets.
 * Bit 6 to 8 – Spare, for future use and set to 0.
 *
 * One and only one of the DROP, FORW and BUFF flags shall be set to 1.
 * The NOCP flag may only be set if the BUFF flag is set.
 * The DUPL flag may be set with any of the DROP, FORW, BUFF and NOCP flags.
 */
    ogs_pfcp_apply_action_t apply_action;

/*
 * 8.2.24 Destination Interface
 *
 * NOTE 1: The "Access" and "Core" values denote a downlink and uplink
 * traffic direction respectively.
 * NOTE 2: LI Function may denote an SX3LIF or an LMISF. See clause 5.7.
 * NOTE 3: For indirect data forwarding, the Source Interface in the PDR and
 * the Destination Interface in the FAR shall both be set to "Access",
 * in the forwarding SGW(s). The Interface value does not infer any
 * traffic direction, in PDRs and FARs set up for indirect data
 * forwarding, i.e. with both the Source and Destination Interfaces set
 * to Access.
 * NOTE 4: For a HTTP redirection, the Source Interface in the PDR to match
 * the uplink packets to be redirected and the Destination Interface in
 * the FAR to enable the HTTP redirection shall both be set to "Access".
 */
    ogs_pfcp_interface_t    dst_if;

    ogs_pfcp_pdr_t          *pdr;
} ogs_pfcp_far_t;

typedef struct ogs_pfcp_urr_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_urr_id_t       id;

    ogs_pfcp_pdr_t          *pdr;
} ogs_pfcp_urr_t;

typedef struct ogs_pfcp_qer_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_qer_id_t       id;

    ogs_pfcp_pdr_t          *pdr;
} ogs_pfcp_qer_t;

typedef struct ogs_pfcp_bar_s {
    ogs_pfcp_bar_id_t       id;

    ogs_pfcp_sess_t         *sess;
} ogs_pfcp_bar_t;

void ogs_pfcp_context_init(void);
void ogs_pfcp_context_final(void);
ogs_pfcp_context_t *ogs_pfcp_self(void);
int ogs_pfcp_context_parse_config(const char *local, const char *remote);

void ogs_pfcp_sess_clear(ogs_pfcp_sess_t *sess);

ogs_pfcp_pdr_t *ogs_pfcp_pdr_add(ogs_pfcp_sess_t *sess);
ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_pdr_id_t id);
ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_or_add(
        ogs_pfcp_sess_t *sess, ogs_pfcp_pdr_id_t id);
void ogs_pfcp_pdr_remove(ogs_pfcp_pdr_t *pdr);
void ogs_pfcp_pdr_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_far_t *ogs_pfcp_far_add(ogs_pfcp_pdr_t *pdr);
ogs_pfcp_far_t *ogs_pfcp_far_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_far_id_t id);
ogs_pfcp_far_t *ogs_pfcp_far_find_or_add(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_far_id_t id);
void ogs_pfcp_far_remove(ogs_pfcp_far_t *far);
void ogs_pfcp_far_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_urr_t *ogs_pfcp_urr_add(ogs_pfcp_pdr_t *pdr);
ogs_pfcp_urr_t *ogs_pfcp_urr_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_urr_id_t id);
ogs_pfcp_urr_t *ogs_pfcp_urr_find_or_add(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_urr_id_t id);
void ogs_pfcp_urr_remove(ogs_pfcp_urr_t *urr);
void ogs_pfcp_urr_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_qer_t *ogs_pfcp_qer_add(ogs_pfcp_pdr_t *pdr);
ogs_pfcp_qer_t *ogs_pfcp_qer_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_qer_id_t id);
ogs_pfcp_qer_t *ogs_pfcp_qer_find_or_add(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_qer_id_t id);
void ogs_pfcp_qer_remove(ogs_pfcp_qer_t *qer);
void ogs_pfcp_qer_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_bar_t *ogs_pfcp_bar_new(ogs_pfcp_sess_t *sess);
void ogs_pfcp_bar_delete(ogs_pfcp_bar_t *bar);

#ifdef __cplusplus
}
#endif

#endif /* OGS_PFCP_CONTEXT_H */
