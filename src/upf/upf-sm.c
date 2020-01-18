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

#include "upf-sm.h"
#include "context.h"
#include "event.h"
#include "pfcp-path.h"
#include "gtp-path.h"

void upf_state_initial(ogs_fsm_t *s, upf_event_t *e)
{
    upf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &upf_state_operational);
}

void upf_state_final(ogs_fsm_t *s, upf_event_t *e)
{
    upf_sm_debug(e);

    ogs_assert(s);
}

void upf_state_operational(ogs_fsm_t *s, upf_event_t *e)
{
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    upf_sess_t *sess = NULL;

    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_node_t *pnode = NULL;
    ogs_pfcp_xact_t *xact = NULL;

    upf_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        rv = upf_pfcp_open();
        if (rv != OGS_OK) {
            ogs_fatal("Can't establish N4-PFCP path");
            break;
        }
        rv = upf_gtp_open();
        if (rv != OGS_OK) {
            ogs_fatal("Can't establish GTP-U path");
            break;
        }

        ogs_list_for_each(&ogs_pfcp_self()->n4_list, pnode) {
            upf_event_t e;
            e.pnode = pnode;

            ogs_fsm_create(&pnode->sm,
                    upf_pfcp_state_initial, upf_pfcp_state_final);
            ogs_fsm_init(&pnode->sm, &e);
        }
        break;
    case OGS_FSM_EXIT_SIG:
        ogs_list_for_each(&ogs_pfcp_self()->n4_list, pnode) {
            upf_event_t e;
            e.pnode = pnode;

            ogs_fsm_fini(&pnode->sm, &e);
            ogs_fsm_delete(&pnode->sm);
        }

        upf_pfcp_close();
        upf_gtp_close();
        break;
    case UPF_EVT_N4_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);
        pnode = e->pnode;
        ogs_assert(pnode);

        if (ogs_pfcp_parse_msg(&pfcp_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_pfcp_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        rv = ogs_pfcp_xact_receive(pnode, &pfcp_message.h, &xact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        e->pfcp_message = &pfcp_message;
        e->pfcp_xact = xact;
        ogs_fsm_dispatch(&pnode->sm, e);
        if (OGS_FSM_CHECK(&pnode->sm, upf_pfcp_state_exception)) {
            ogs_error("PFCP state machine exception");
            break;
        }

        ogs_pkbuf_free(recvbuf);
        break;
    case UPF_EVT_N4_TIMER:
    case UPF_EVT_N4_NO_HEARTBEAT:
        pnode = e->pnode;
        ogs_assert(pnode);
        ogs_assert(OGS_FSM_STATE(&pnode->sm));

        ogs_fsm_dispatch(&pnode->sm, e);
        break;
    default:
        ogs_error("No handler for event %s", upf_event_get_name(e));
        break;
    }
}
