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

#include "smf-sm.h"
#include "smf-context.h"
#include "smf-event.h"
#include "smf-gtp-path.h"
#include "smf-fd-path.h"
#include "smf-pfcp-path.h"
#include "smf-s5c-handler.h"
#include "smf-gx-handler.h"

void smf_state_initial(ogs_fsm_t *s, smf_event_t *e)
{
    smf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &smf_state_operational);
}

void smf_state_final(ogs_fsm_t *s, smf_event_t *e)
{
    smf_sm_debug(e);

    ogs_assert(s);
}

void smf_state_operational(ogs_fsm_t *s, smf_event_t *e)
{
    int rv;
    ogs_pkbuf_t *recvbuf = NULL;
    smf_sess_t *sess = NULL;

    ogs_gtp_message_t gtp_message;
    ogs_pkbuf_t *gtpbuf = NULL;
    ogs_gtp_node_t *gnode = NULL;
    ogs_gtp_xact_t *gxact = NULL;

    ogs_pkbuf_t *gxbuf = NULL;
    ogs_diam_gx_message_t *gx_message = NULL;

    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_node_t *pnode = NULL;
    ogs_pfcp_xact_t *pxact = NULL;

    smf_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        rv = smf_gtp_open();
        if (rv != OGS_OK) {
            ogs_fatal("Can't establish S11-GTP path");
            break;
        }
        rv = smf_pfcp_open();
        if (rv != OGS_OK) {
            ogs_fatal("Can't establish N4-PFCP path");
            break;
        }
        break;
    case OGS_FSM_EXIT_SIG:
        smf_gtp_close();
        smf_pfcp_close();
        break;
    case SMF_EVT_S5C_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);

        rv = ogs_gtp_parse_msg(&gtp_message, recvbuf);
        ogs_assert(rv == OGS_OK);

        if (gtp_message.h.teid != 0) {
            sess = smf_sess_find_by_teid(gtp_message.h.teid);
        }

        if (sess) {
            gnode = sess->gnode;
            ogs_assert(gnode);
        } else {
            gnode = e->gnode;
            ogs_assert(gnode);
        }

        rv = ogs_gtp_xact_receive(gnode, &gtp_message.h, &gxact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        switch(gtp_message.h.type) {
        case OGS_GTP_CREATE_SESSION_REQUEST_TYPE:
            if (gtp_message.h.teid == 0) {
                ogs_assert(!sess);
                sess = smf_sess_add_by_message(&gtp_message);
                if (sess)
                    OGS_SETUP_GTP_NODE(sess, gnode);
            }
            smf_s5c_handle_create_session_request(
                sess, gxact, &gtp_message.create_session_request);
            break;
        case OGS_GTP_DELETE_SESSION_REQUEST_TYPE:
            smf_s5c_handle_delete_session_request(
                sess, gxact, &gtp_message.delete_session_request);
            break;
        case OGS_GTP_CREATE_BEARER_RESPONSE_TYPE:
            smf_s5c_handle_create_bearer_response(
                sess, gxact, &gtp_message.create_bearer_response);
            break;
        case OGS_GTP_UPDATE_BEARER_RESPONSE_TYPE:
            smf_s5c_handle_update_bearer_response(
                sess, gxact, &gtp_message.update_bearer_response);
            break;
        case OGS_GTP_DELETE_BEARER_RESPONSE_TYPE:
            smf_s5c_handle_delete_bearer_response(
                sess, gxact, &gtp_message.delete_bearer_response);
            break;
        default:
            ogs_warn("Not implmeneted(type:%d)", gtp_message.h.type);
            break;
        }
        ogs_pkbuf_free(recvbuf);
        break;

    case SMF_EVT_GX_MESSAGE:
        ogs_assert(e);

        gxbuf = e->pkbuf;
        ogs_assert(gxbuf);
        gx_message = (ogs_diam_gx_message_t *)gxbuf->data;
        ogs_assert(gx_message);

        sess = e->sess;
        ogs_assert(sess);

        switch(gx_message->cmd_code) {
        case OGS_DIAM_GX_CMD_CODE_CREDIT_CONTROL:
            gxact = e->gxact;
            ogs_assert(gxact);

            if (gx_message->result_code == ER_DIAMETER_SUCCESS) {
                switch(gx_message->cc_request_type) {
                case OGS_DIAM_GX_CC_REQUEST_TYPE_INITIAL_REQUEST:
                    smf_gx_handle_cca_initial_request(
                            sess, gx_message, gxact);
                    break;
                case OGS_DIAM_GX_CC_REQUEST_TYPE_TERMINATION_REQUEST:
                    smf_gx_handle_cca_termination_request(
                            sess, gx_message, gxact);
                    break;
                default:
                    ogs_error("Not implemented(%d)",
                            gx_message->cc_request_type);
                    break;
                }
            } else
                ogs_error("Diameter Error(%d)", gx_message->result_code);

            ogs_pkbuf_free(gtpbuf);
            break;
        case OGS_DIAM_GX_CMD_RE_AUTH:
            smf_gx_handle_re_auth_request(sess, gx_message);
            break;
        default:
            ogs_error("Invalid type(%d)", gx_message->cmd_code);
            break;
        }

        ogs_diam_gx_message_free(gx_message);
        ogs_pkbuf_free(gxbuf);
        break;
    case SMF_EVT_N4_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);

        rv = ogs_pfcp_parse_msg(&pfcp_message, recvbuf);
        ogs_assert(rv == OGS_OK);

        if (pfcp_message.h.seid != 0) {
            sess = smf_sess_find_by_seid(pfcp_message.h.seid);
        }

        if (sess) {
            pnode = sess->pnode;
            ogs_assert(pnode);

        } else {
            pnode = e->pnode;
            ogs_assert(pnode);
        }

        rv = ogs_pfcp_xact_receive(pnode, &pfcp_message.h, &pxact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        switch (pfcp_message.h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            break;
#if 0
        case OGS_PFCP_PFD_MANAGEMENT_REQUEST_TYPE:
            break;
        case OGS_PFCP_PFD_MANAGEMENT_RESPONSE_TYPE:
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            break;
        case OGS_PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE:
            break;
        case OGS_PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE:
            break;
        case OGS_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
            break;
        case OGS_PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE:
            break;
        case OGS_PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE:
            break;
        case OGS_PFCP_NODE_REPORT_REQUEST_TYPE:
            break;
        case OGS_PFCP_NODE_REPORT_RESPONSE_TYPE:
            break;
        case OGS_PFCP_SESSION_SET_DELETION_REQUEST_TYPE:
            break;
        case OGS_PFCP_SESSION_SET_DELETION_RESPONSE_TYPE:
            break;
        case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
            break;
        case OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE:
            break;
        case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
            break;
        case OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE:
            break;
        case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE:
            break;
        case OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE:
            break;
        case OGS_PFCP_SESSION_REPORT_REQUEST_TYPE:
            break;
        case OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE:
            break;
#endif
        default:
            ogs_error("Not implemented PFCP message type[%d]",
                    pfcp_message.h.type);
            break;
        }

        ogs_pkbuf_free(recvbuf);
        break;
    default:
        ogs_error("No handler for event %s", smf_event_get_name(e));
        break;
    }
}
