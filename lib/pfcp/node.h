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

#ifndef OGS_PFCP_NODE_H
#define OGS_PFCP_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_SETUP_PFCP_NODE(__cTX, __pNODE) \
    do { \
        ogs_assert((__cTX)); \
        ogs_assert((__pNODE)); \
        (__cTX)->node = __pNODE; \
    } while(0)

/**
 * This structure represents the commonalities of PFCP CP node such as SMF/UPF.
 * Some of members may not be used by the specific type of node */
typedef struct ogs_pfcp_cp_node_s {
    ogs_lnode_t     lnode;          /* A node of list_t */

    ogs_sockaddr_t  *sa_list;       /* Socket Address List Candidate */

    ogs_sock_t      *sock;          /* Socket Instance */
    ogs_sockaddr_t  addr;           /* Remote Address */

    ogs_ip_t        ip;             /* F-SEID IP address Duplicate Check */

    ogs_list_t      local_list;    
    ogs_list_t      remote_list;   

    ogs_fsm_t       sm;             /* A state machine */
    ogs_timer_t     *t_association; /* timer to retry to associate peer node */
    ogs_timer_t     *t_heartbeat;   /* heartbeat timer to check UPF aliveness */

    uint16_t        tac[OGS_MAX_NUM_OF_TAI];
    uint8_t         num_of_tac;

    ogs_list_t      up_list;        /* User Plane IP Resource Information */
} ogs_pfcp_cp_node_t;

/**
 * This structure represents the User Plane IP Resource Information.
 */
typedef struct ogs_pfcp_up_node_s {
    ogs_lnode_t     lnode;      /* A node of list_t */

    ogs_sockaddr_t  *addr;      /* addr or addr6 is needed */
    ogs_sockaddr_t  *addr6;

    struct {
        uint8_t num_of_bits;    /* Not available if num_of_bits == 0 */
        uint8_t value;
    } teid_range;

    char apn[OGS_MAX_APN_LEN];  /* Not available if strlen(apn) == 0 */
    int8_t source_interface;    /* Not available if source interface == -1 */
} ogs_pfcp_up_node_t;

int ogs_pfcp_node_init(int cp_size, int up_size);
int ogs_pfcp_node_final(void);

ogs_pfcp_cp_node_t *ogs_pfcp_cp_node_new(ogs_sockaddr_t *sa_list);
void ogs_pfcp_cp_node_free(ogs_pfcp_cp_node_t *node);

ogs_pfcp_cp_node_t *ogs_pfcp_cp_node_add(
        ogs_list_t *list, ogs_sockaddr_t *addr);
ogs_pfcp_cp_node_t *ogs_pfcp_cp_node_find(
        ogs_list_t *list, ogs_sockaddr_t *addr);
void ogs_pfcp_cp_node_remove(ogs_list_t *list, ogs_pfcp_cp_node_t *node);
void ogs_pfcp_cp_node_remove_all(ogs_list_t *list);

ogs_pfcp_up_node_t *ogs_pfcp_up_node_new(
        ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6);
void ogs_pfcp_up_node_free(ogs_pfcp_up_node_t *node);

ogs_pfcp_up_node_t *ogs_pfcp_up_node_add(
        ogs_list_t *list, ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6);
void ogs_pfcp_up_node_remove(
        ogs_list_t *list, ogs_pfcp_up_node_t *node);
void ogs_pfcp_up_node_remove_all(ogs_list_t *list);

#ifdef __cplusplus
}
#endif

#endif /* OGS_PFCP_NODE_H */
