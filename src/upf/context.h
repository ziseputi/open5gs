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

#ifndef UPF_CONTEXT_H
#define UPF_CONTEXT_H

#include "upf-config.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "ogs-gtp.h"
#include "ogs-diameter-gx.h"
#include "ogs-pfcp.h"
#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NUM_OF_DEV          16
#define MAX_NUM_OF_SUBNET       16

extern int __upf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __upf_log_domain

typedef struct upf_context_s {
    const char*         diam_conf_path;   /* UPF Diameter conf path */
    ogs_diam_config_t   *diam_config;     /* UPF Diameter config */

    uint32_t        gtpc_port;      /* Default: UPF GTP-C local port */
    uint32_t        gtpu_port;      /* Default: UPF GTP-U local port */
    const char      *tun_ifname;    /* Default: ogstun */

    ogs_list_t      gtpc_list;      /* UPF GTPC IPv4 Server List */
    ogs_list_t      gtpc_list6;     /* UPF GTPC IPv6 Server List */
    ogs_sock_t      *gtpc_sock;     /* UPF GTPC IPv4 Socket */
    ogs_sock_t      *gtpc_sock6;    /* UPF GTPC IPv6 Socket */
    ogs_sockaddr_t  *gtpc_addr;     /* UPF GTPC IPv4 Address */
    ogs_sockaddr_t  *gtpc_addr6;    /* UPF GTPC IPv6 Address */

    ogs_list_t      gtpu_list;      /* UPF GTPU IPv4 Server List */
    ogs_list_t      gtpu_list6;     /* UPF GTPU IPv6 Server List */
    ogs_sock_t      *gtpu_sock;     /* UPF GTPU IPv4 Socket */
    ogs_sock_t      *gtpu_sock6;    /* UPF GTPU IPv6 Socket */
    ogs_sockaddr_t  *gtpu_addr;     /* UPF GTPU IPv4 Address */
    ogs_sockaddr_t  *gtpu_addr6;    /* UPF GTPU IPv6 Address */

    ogs_list_t      dev_list;       /* UPF Tun Device List */
    ogs_list_t      subnet_list;    /* UPF UE Subnet List */

    ogs_queue_t     *queue;         /* Queue for processing UPF control */
    ogs_timer_mgr_t *timer_mgr;     /* Timer Manager */
    ogs_pollset_t   *pollset;       /* Poll Set for I/O Multiplexing */

#define MAX_NUM_OF_DNS              2
    const char      *dns[MAX_NUM_OF_DNS];
    const char      *dns6[MAX_NUM_OF_DNS];

#define MAX_NUM_OF_P_CSCF           16
    const char      *p_cscf[MAX_NUM_OF_P_CSCF];
    int             num_of_p_cscf;
    int             p_cscf_index;
    const char      *p_cscf6[MAX_NUM_OF_P_CSCF];
    int             num_of_p_cscf6;
    int             p_cscf6_index;

    ogs_list_t      sgw_s5c_list;   /* SGW GTPC Node List */
    ogs_list_t      sgw_s5u_list;   /* SGW GTPU Node List */
    ogs_list_t      ip_pool_list;

    ogs_hash_t      *sess_hash;     /* hash table (IMSI+APN) */
} upf_context_t;

typedef struct upf_subnet_s upf_subnet_t;
typedef struct upf_ue_ip_s {
    uint32_t        addr[4];
    bool            static_ip;

    /* Related Context */
    upf_subnet_t    *subnet;
} upf_ue_ip_t;

typedef struct upf_dev_s {
    ogs_lnode_t     lnode;

    char            ifname[IFNAMSIZ];
    ogs_socket_t    fd;

    ogs_sockaddr_t  *link_local_addr;
    ogs_poll_t      *poll;
} upf_dev_t;

typedef struct upf_subnet_s {
    ogs_lnode_t     node;

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
    OGS_POOL(pool, upf_ue_ip_t);

    upf_dev_t       *dev;           /* Related Context */
} upf_subnet_t;

typedef struct upf_sess_s {
    ogs_lnode_t     lnode;
    uint32_t        index;          /**< An index of this node */

    uint32_t        upf_s5c_teid;   /* UPF-S5C-TEID is derived from INDEX */
    uint32_t        sgw_s5c_teid;   /* SGW-S5C-TEID is received from SGW */

    char            *gx_sid;        /* Gx Session ID */

    ogs_pfcp_sess_t pfcp;

    /* IMSI */
    uint8_t         imsi[OGS_MAX_IMSI_LEN];
    int             imsi_len;
    char            imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    /* APN Configuration */
    ogs_pdn_t       pdn;
    upf_ue_ip_t     *ipv4;
    upf_ue_ip_t     *ipv6;

    /* User-Lication-Info */
    ogs_tai_t       tai;
    ogs_e_cgi_t     e_cgi;

    uint8_t         hash_keybuf[OGS_MAX_IMSI_LEN+OGS_MAX_APN_LEN+1];
    int             hash_keylen;

    /* Stored GTP message */
    ogs_gtp_create_session_request_t *create_session_request;
    ogs_gtp_delete_session_request_t *delete_session_request;

    ogs_list_t      bearer_list;

    /* Related Context */
    ogs_gtp_node_t  *gnode;
} upf_sess_t;

typedef struct upf_bearer_s {
    ogs_lnode_t     lnode; /**< A node of list_t */
    uint32_t        index;

    uint8_t         ebi;

    uint32_t        upf_s5u_teid;   /* UPF_S5U is derived from INDEX */
    uint32_t        sgw_s5u_teid;   /* SGW_S5U is received from SGW */

    char            *name;          /* PCC Rule Name */
    ogs_qos_t       qos;            /* QoS Infomration */

    /* Packet Filter Identifier Generator(1~15) */
    uint8_t         pf_identifier;
    /* Packet Filter List */
    ogs_list_t      pf_list;

    upf_sess_t      *sess;
    ogs_gtp_node_t  *gnode;
} upf_bearer_t;

typedef struct upf_rule_s {
    uint8_t proto;
ED5(uint8_t ipv4_local:1;,
    uint8_t ipv4_remote:1;,
    uint8_t ipv6_local:1;,
    uint8_t ipv6_remote:1;,
    uint8_t reserved:4;)
    struct {
        struct {
            uint32_t addr[4];
            uint32_t mask[4];
        } local;
        struct {
            uint32_t addr[4];
            uint32_t mask[4];
        } remote;
    } ip;
    struct {
        struct {
            uint16_t low;
            uint16_t high;
        } local;
        struct {
            uint16_t low;
            uint16_t high;
        } remote;
    } port;
} upf_rule_t;

typedef struct upf_pf_s {
    ogs_lnode_t     lnode;

ED3(uint8_t spare:2;,
    uint8_t direction:2;,
    uint8_t identifier:4;)
    upf_rule_t      rule;

    upf_bearer_t    *bearer;
} upf_pf_t;

void upf_context_init(void);
void upf_context_final(void);
upf_context_t *upf_self(void);

int upf_context_parse_config(void);

upf_sess_t *upf_sess_add_by_message(ogs_gtp_message_t *message);

upf_sess_t *upf_sess_add(
        uint8_t *imsi, int imsi_len, char *apn,
        uint8_t pdn_type, uint8_t ebi, ogs_paa_t *addr);

int upf_sess_remove(upf_sess_t *sess);
void upf_sess_remove_all(void);
upf_sess_t *upf_sess_find(uint32_t index);
upf_sess_t *upf_sess_find_by_teid(uint32_t teid);
upf_sess_t *upf_sess_find_by_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_imsi_apn(uint8_t *imsi, int imsi_len, char *apn);

upf_bearer_t *upf_bearer_add(upf_sess_t *sess);
int upf_bearer_remove(upf_bearer_t *bearer);
void upf_bearer_remove_all(upf_sess_t *sess);
upf_bearer_t *upf_bearer_find(uint32_t index);
upf_bearer_t *upf_bearer_find_by_upf_s5u_teid(uint32_t upf_s5u_teid);
upf_bearer_t *upf_bearer_find_by_ebi(upf_sess_t *sess, uint8_t ebi);
upf_bearer_t *upf_bearer_find_by_name(upf_sess_t *sess, char *name);
upf_bearer_t *upf_bearer_find_by_qci_arp(upf_sess_t *sess, 
                                uint8_t qci,
                                uint8_t priority_level,
                                uint8_t pre_emption_capability,
                                uint8_t pre_emption_vulnerability);
upf_bearer_t *upf_default_bearer_in_sess(upf_sess_t *sess);
upf_bearer_t *upf_bearer_first(upf_sess_t *sess);
upf_bearer_t *upf_bearer_next(upf_bearer_t *bearer);

upf_pf_t *upf_pf_add(upf_bearer_t *bearer, uint32_t precedence);
int upf_pf_remove(upf_pf_t *pf);
void upf_pf_remove_all(upf_bearer_t *bearer);
upf_pf_t *upf_pf_find_by_id(upf_bearer_t *upf_bearer, uint8_t id);
upf_pf_t *upf_pf_first(upf_bearer_t *bearer);
upf_pf_t *upf_pf_next(upf_pf_t *pf);

int upf_ue_pool_generate(void);
upf_ue_ip_t *upf_ue_ip_alloc(int family, const char *apn, uint8_t *addr);
int upf_ue_ip_free(upf_ue_ip_t *ip);

upf_dev_t *upf_dev_add(const char *ifname);
int upf_dev_remove(upf_dev_t *dev);
void upf_dev_remove_all(void);
upf_dev_t *upf_dev_find_by_ifname(const char *ifname);
upf_dev_t *upf_dev_first(void);
upf_dev_t *upf_dev_next(upf_dev_t *dev);

upf_subnet_t *upf_subnet_add(
        const char *ipstr, const char *mask_or_numbits,
        const char *apn, const char *ifname);
upf_subnet_t *upf_subnet_next(upf_subnet_t *subnet);
int upf_subnet_remove(upf_subnet_t *subnet);
void upf_subnet_remove_all(void);
upf_subnet_t *upf_subnet_first(void);
upf_subnet_t *gw_subnet_next(upf_subnet_t *subnet);

void stats_add_session(void);
void stats_remove_session(void);

#ifdef __cplusplus
}
#endif

#endif /* UPF_CONTEXT_H */
