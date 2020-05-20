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

#define OGS_MAX_NUM_OF_DEV      16
#define OGS_MAX_NUM_OF_SUBNET   16

typedef struct ogs_pfcp_node_s ogs_pfcp_node_t;

typedef struct ogs_pfcp_context_s {
    uint32_t        pfcp_port;      /* PFCP local port */
    const char      *tun_ifname;    /* PFCP TUN Interface Name */

    ogs_list_t      pfcp_list;      /* PFCP IPv4 Server List */
    ogs_list_t      pfcp_list6;     /* PFCP IPv6 Server List */
    ogs_sock_t      *pfcp_sock;     /* PFCP IPv4 Socket */
    ogs_sock_t      *pfcp_sock6;    /* PFCP IPv6 Socket */
    ogs_sockaddr_t  *pfcp_addr;     /* PFCP IPv4 Address */
    ogs_sockaddr_t  *pfcp_addr6;    /* PFCP IPv6 Address */

    uint32_t        pfcp_started;   /* UTC time when the PFCP entity started */

    ogs_list_t      n4_list;        /* PFCP Node List */
    ogs_pfcp_node_t *node;    /* Iterator for Peer round-robin */

    ogs_list_t      dev_list;       /* Tun Device List */
    ogs_list_t      subnet_list;    /* UE Subnet List */

    ogs_hash_t      *pdr_hash;      /* hash table (UPF-N3-TEID) */
} ogs_pfcp_context_t;

#define OGS_SETUP_PFCP_NODE(__cTX, __pNODE) \
    do { \
        ogs_assert((__cTX)); \
        ogs_assert((__pNODE)); \
        (__cTX)->pfcp_node = __pNODE; \
    } while(0)

typedef struct ogs_pfcp_node_s {
    ogs_lnode_t     lnode;          /* A node of list_t */

    ogs_sockaddr_t  *sa_list;       /* Socket Address List Candidate */

    ogs_sock_t      *sock;          /* Socket Instance */
    ogs_sockaddr_t  addr;           /* Remote Address */

    ogs_list_t      local_list;    
    ogs_list_t      remote_list;   

    ogs_fsm_t       sm;             /* A state machine */
    ogs_timer_t     *t_association; /* timer to retry to associate peer node */
    ogs_timer_t     *t_heartbeat;   /* heartbeat timer to check UPF aliveness */

    uint16_t        tac[OGS_MAX_NUM_OF_TAI];
    uint8_t         num_of_tac;

    ogs_list_t      gtpu_resource_list; /* User Plane IP Resource Information */
} ogs_pfcp_node_t;

typedef struct ogs_pfcp_gtpu_resource_s {
    ogs_lnode_t lnode;

    ogs_pfcp_user_plane_ip_resource_info_t info;
} __attribute__ ((packed)) ogs_pfcp_gtpu_resource_t;

typedef struct ogs_pfcp_pdr_s ogs_pfcp_pdr_t;
typedef struct ogs_pfcp_far_s ogs_pfcp_far_t;
typedef struct ogs_pfcp_urr_s ogs_pfcp_urr_t;
typedef struct ogs_pfcp_qer_s ogs_pfcp_qer_t;
typedef struct ogs_pfcp_bar_s ogs_pfcp_bar_t;

typedef struct ogs_pfcp_sess_s {
    ogs_list_t          pdr_list;       /* PDR List */
    ogs_list_t          far_list;       /* FAR List */
    ogs_list_t          urr_list;       /* URR List */
    ogs_list_t          qer_list;       /* QER List */
    ogs_pfcp_bar_t      *bar;           /* BAR Item */

    /* Related Context */
    ogs_pfcp_pdr_t      *default_pdr;   /* Used by UPF */
} ogs_pfcp_sess_t;

typedef struct ogs_pfcp_pdr_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_pdr_id_t       id;
    ogs_pfcp_precedence_t   precedence;
    ogs_pfcp_interface_t    src_if;

    ogs_pfcp_f_teid_t       f_teid;
    ogs_pfcp_outer_header_removal_t outer_header_removal;

    ogs_pfcp_far_t          *far;
    ogs_pfcp_urr_t          *urr;
    ogs_pfcp_qer_t          *qer;

    int                     num_of_flow;
    char                    *flow_description[OGS_MAX_NUM_OF_RULE];

    /* Related Context */
    ogs_pfcp_sess_t         *sess;
} ogs_pfcp_pdr_t;

typedef struct ogs_pfcp_far_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_far_id_t       id;
    ogs_pfcp_apply_action_t apply_action;
    ogs_pfcp_interface_t    dst_if;
    ogs_pfcp_outer_header_creation_t outer_header_creation;
    int                     outer_header_creation_len;

    /* Related Context */
    ogs_pfcp_sess_t         *sess;
    void                    *gnode;
} ogs_pfcp_far_t;

typedef struct ogs_pfcp_urr_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_urr_id_t       id;

    ogs_pfcp_sess_t         *sess;
} ogs_pfcp_urr_t;

typedef struct ogs_pfcp_qer_s {
    ogs_lnode_t             lnode;

    ogs_pfcp_qer_id_t       id;

    ogs_pfcp_gate_status_t  gate_status;
    ogs_pfcp_bitrate_t      mbr;
    ogs_pfcp_bitrate_t      gbr;

    ogs_pfcp_sess_t         *sess;
} ogs_pfcp_qer_t;

typedef struct ogs_pfcp_bar_s {
    ogs_pfcp_bar_id_t       id;

    ogs_pfcp_sess_t         *sess;
} ogs_pfcp_bar_t;

typedef struct ogs_pfcp_subnet_s ogs_pfcp_subnet_t;
typedef struct ogs_pfcp_ue_ip_s {
    uint32_t        addr[4];
    bool            static_ip;

    /* Related Context */
    ogs_pfcp_subnet_t    *subnet;
} ogs_pfcp_ue_ip_t;

typedef struct ogs_pfcp_dev_s {
    ogs_lnode_t     lnode;

    char            ifname[OGS_MAX_IFNAME_LEN];
    ogs_socket_t    fd;

    ogs_sockaddr_t  *link_local_addr;
    ogs_poll_t      *poll;
} ogs_pfcp_dev_t;

typedef struct ogs_pfcp_subnet_s {
    ogs_lnode_t     lnode;

    ogs_ipsubnet_t  sub;                /* Subnet : cafe::0/64 */
    ogs_ipsubnet_t  gw;                 /* Gateway : cafe::1 */
    char            apn[OGS_MAX_APN_LEN];   /* APN : "internet", "volte", .. */

#define MAX_NUM_OF_SUBNET_RANGE         16
    struct {
        const char *low;
        const char *high;
    } range[MAX_NUM_OF_SUBNET_RANGE];
    int num_of_range;

    int             family;         /* AF_INET or AF_INET6 */
    uint8_t         prefixlen;      /* prefixlen */
    OGS_POOL(pool, ogs_pfcp_ue_ip_t);

    ogs_pfcp_dev_t  *dev;           /* Related Context */
} ogs_pfcp_subnet_t;

void ogs_pfcp_context_init(int num_of_gtpu_resource);
void ogs_pfcp_context_final(void);
ogs_pfcp_context_t *ogs_pfcp_self(void);
int ogs_pfcp_context_parse_config(const char *local, const char *remote);

ogs_pfcp_node_t *ogs_pfcp_node_new(ogs_sockaddr_t *sa_list);
void ogs_pfcp_node_free(ogs_pfcp_node_t *node);

ogs_pfcp_node_t *ogs_pfcp_node_add(
        ogs_list_t *list, ogs_sockaddr_t *addr);
ogs_pfcp_node_t *ogs_pfcp_node_find(
        ogs_list_t *list, ogs_sockaddr_t *addr);
void ogs_pfcp_node_remove(ogs_list_t *list, ogs_pfcp_node_t *node);
void ogs_pfcp_node_remove_all(ogs_list_t *list);

ogs_pfcp_gtpu_resource_t *ogs_pfcp_gtpu_resource_add(ogs_list_t *list,
        ogs_pfcp_user_plane_ip_resource_info_t *info);
ogs_pfcp_gtpu_resource_t *ogs_pfcp_gtpu_resource_find(ogs_list_t *list,
        char *apn, ogs_pfcp_interface_t source_interface);
void ogs_pfcp_gtpu_resource_remove(ogs_list_t *list,
        ogs_pfcp_gtpu_resource_t *resource);
void ogs_pfcp_gtpu_resource_remove_all(ogs_list_t *list);

#define OGS_SETUP_DEFAULT_PDR(__sESS, __pDR) \
    do { \
        ogs_assert((__sESS)); \
        ogs_assert((__pDR)); \
        (__sESS)->default_pdr = __pDR; \
        ogs_assert((__sESS)->default_pdr); \
    } while(0)
ogs_pfcp_pdr_t *ogs_pfcp_sess_default_pdr(ogs_pfcp_sess_t *sess);
void ogs_pfcp_sess_clear(ogs_pfcp_sess_t *sess);

ogs_pfcp_pdr_t *ogs_pfcp_pdr_add(ogs_pfcp_sess_t *sess);
ogs_pfcp_pdr_t *ogs_pfcp_pdr_find(
        ogs_pfcp_sess_t *sess, ogs_pfcp_pdr_id_t id);
ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_by_teid(uint32_t teid);
ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_or_add(
        ogs_pfcp_sess_t *sess, ogs_pfcp_pdr_id_t id);
void ogs_pfcp_pdr_reorder_by_precedence(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_precedence_t precedence);
void ogs_pfcp_pdr_associate_far(ogs_pfcp_pdr_t *pdr, ogs_pfcp_far_t *far);
void ogs_pfcp_pdr_associate_urr(ogs_pfcp_pdr_t *pdr, ogs_pfcp_urr_t *urr);
void ogs_pfcp_pdr_associate_qer(ogs_pfcp_pdr_t *pdr, ogs_pfcp_qer_t *qer);
void ogs_pfcp_pdr_remove(ogs_pfcp_pdr_t *pdr);
void ogs_pfcp_pdr_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_far_t *ogs_pfcp_far_add(ogs_pfcp_sess_t *sess);
ogs_pfcp_far_t *ogs_pfcp_far_find(
        ogs_pfcp_sess_t *sess, ogs_pfcp_far_id_t id);
ogs_pfcp_far_t *ogs_pfcp_far_find_or_add(
        ogs_pfcp_sess_t *sess, ogs_pfcp_far_id_t id);
void ogs_pfcp_far_remove(ogs_pfcp_far_t *far);
void ogs_pfcp_far_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_urr_t *ogs_pfcp_urr_add(ogs_pfcp_sess_t *sess);
ogs_pfcp_urr_t *ogs_pfcp_urr_find(
        ogs_pfcp_sess_t *sess, ogs_pfcp_urr_id_t id);
ogs_pfcp_urr_t *ogs_pfcp_urr_find_or_add(
        ogs_pfcp_sess_t *sess, ogs_pfcp_urr_id_t id);
void ogs_pfcp_urr_remove(ogs_pfcp_urr_t *urr);
void ogs_pfcp_urr_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_qer_t *ogs_pfcp_qer_add(ogs_pfcp_sess_t *sess);
ogs_pfcp_qer_t *ogs_pfcp_qer_find(
        ogs_pfcp_sess_t *sess, ogs_pfcp_qer_id_t id);
ogs_pfcp_qer_t *ogs_pfcp_qer_find_or_add(
        ogs_pfcp_sess_t *sess, ogs_pfcp_qer_id_t id);
void ogs_pfcp_qer_remove(ogs_pfcp_qer_t *qer);
void ogs_pfcp_qer_remove_all(ogs_pfcp_sess_t *sess);

ogs_pfcp_bar_t *ogs_pfcp_bar_new(ogs_pfcp_sess_t *sess);
void ogs_pfcp_bar_delete(ogs_pfcp_bar_t *bar);

int ogs_pfcp_ue_pool_generate(void);
ogs_pfcp_ue_ip_t *ogs_pfcp_ue_ip_alloc(
        int family, const char *apn, uint8_t *addr);
void ogs_pfcp_ue_ip_free(ogs_pfcp_ue_ip_t *ip);

ogs_pfcp_dev_t *ogs_pfcp_dev_add(const char *ifname);
void ogs_pfcp_dev_remove(ogs_pfcp_dev_t *dev);
void ogs_pfcp_dev_remove_all(void);
ogs_pfcp_dev_t *ogs_pfcp_dev_find_by_ifname(const char *ifname);

ogs_pfcp_subnet_t *ogs_pfcp_subnet_add(
        const char *ipstr, const char *mask_or_numbits,
        const char *apn, const char *ifname);
ogs_pfcp_subnet_t *ogs_pfcp_subnet_next(ogs_pfcp_subnet_t *subnet);
void ogs_pfcp_subnet_remove(ogs_pfcp_subnet_t *subnet);
void ogs_pfcp_subnet_remove_all(void);

#ifdef __cplusplus
}
#endif

#endif /* OGS_PFCP_CONTEXT_H */
