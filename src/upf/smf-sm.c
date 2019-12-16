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

#include "context.h"
#include "event.h"
#include "timer.h"
#include "upf-sm.h"

#include "pfcp-path.h"
#if 0
#include "upf-n4-handler.h"
#endif

void upf_smf_state_initial(ogs_fsm_t *s, upf_event_t *e)
{
    int rv;
    ogs_pfcp_node_t *pnode = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    pnode = e->pnode;
    ogs_assert(pnode);

    rv = ogs_pfcp_connect(
            upf_self()->pfcp_sock, upf_self()->pfcp_sock6, pnode);
    ogs_assert(rv == OGS_OK);

    pnode->t_conn = ogs_timer_add(upf_self()->timer_mgr,
            upf_timer_connect_to_upf, pnode);
    ogs_assert(pnode->t_conn);

    OGS_FSM_TRAN(s, &upf_smf_state_will_connect);
}

void upf_smf_state_final(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *pnode = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    pnode = e->pnode;
    ogs_assert(pnode);

    ogs_timer_delete(pnode->t_conn);
}

void upf_smf_state_will_connect(ogs_fsm_t *s, upf_event_t *e)
{
    char buf[OGS_ADDRSTRLEN];

    ogs_pfcp_node_t *pnode = NULL;
    ogs_sockaddr_t *addr = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    pnode = e->pnode;
    ogs_assert(pnode);

    ogs_assert(pnode->t_conn);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
#if 0
        ogs_timer_start(pnode->t_conn,
                upf_timer_cfg(UPF_TIMER_CONNECT_TO_UPF)->duration);

        upf_pfcp_send_association_setup_request(pnode);
#endif
        break;
    case OGS_FSM_EXIT_SIG:
#if 0
        ogs_timer_stop(pnode->t_conn);
#endif
        break;
    case UPF_EVT_N4_TIMER:
        switch(e->timer_id) {
        case UPF_TIMER_CONNECT_TO_UPF:
            pnode = e->pnode;
            ogs_assert(pnode);
            addr = pnode->sa_list;
            ogs_assert(addr);

            ogs_warn("Connect to UPF [%s]:%d failed",
                        OGS_ADDR(addr, buf), OGS_PORT(addr));

            ogs_assert(pnode->t_conn);
            ogs_timer_start(pnode->t_conn,
                upf_timer_cfg(UPF_TIMER_CONNECT_TO_UPF)->duration);

            upf_pfcp_send_association_setup_request(pnode);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_MESSAGE:
        printf("UPF_EVT_N4_MESSAGE\n");
#if 0
        OGS_FSM_TRAN(s, upf_smf_state_connected);
#endif
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_smf_state_connected(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *pnode = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t type;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    pnode = e->pnode;
    ogs_assert(pnode);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    case UPF_EVT_N4_TIMER:
#if 0
        upf_smf_close(pnode);
        OGS_FSM_TRAN(s, upf_smf_state_will_connect);
#endif
        break;
    case UPF_EVT_N4_MESSAGE:
        pkbuf = e->pkbuf;
        ogs_assert(pkbuf);
        type = *(unsigned char *)(pkbuf->data);
        switch (type) {
#if 0
        case N4_LOCATION_UPDATE_ACCEPT:
            sgsap_handle_location_update_accept(pnode, pkbuf);
            break;
        case N4_LOCATION_UPDATE_REJECT:
            sgsap_handle_location_update_reject(upf, pkbuf);
            break;
        case N4_EPS_DETACH_ACK:
        case N4_IMSI_DETACH_ACK:
            sgsap_handle_detach_ack(upf, pkbuf);
            break;
        case N4_PAGING_REQUEST:
            sgsap_handle_paging_request(upf, pkbuf);
            break;
        case N4_DOWNLINK_UNITDATA:
            sgsap_handle_downlink_unitdata(upf, pkbuf);
            break;
        case N4_RESET_INDICATION:
            sgsap_handle_reset_indication(upf, pkbuf);

            upf_smf_close(upf);
            OGS_FSM_TRAN(s, upf_smf_state_will_connect);
            break;
        case N4_RELEASE_REQUEST:
            sgsap_handle_release_request(upf, pkbuf);
            break;
        case N4_MM_INFORMATION_REQUEST:
            sgsap_handle_mm_information_request(upf, pkbuf);
            break;
#endif
        default:
            ogs_warn("Unknown Message Type: [%d]", type);
            break;
        }
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_smf_state_exception(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}
