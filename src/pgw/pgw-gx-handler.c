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

#include "pgw-context.h"
#include "pgw-gtp-path.h"
#include "pgw-s5c-build.h"
#include "pgw-gx-handler.h"
#include "pgw-ipfw.h"

#include "ipfw/ipfw2.h"

static void encode_traffic_flow_template(
        ogs_gtp_tft_t *tft, pgw_bearer_t *bearer);
static void bearer_binding(pgw_sess_t *sess, ogs_diam_gx_message_t *gx_message);

static void timeout(ogs_gtp_xact_t *xact, void *data)
{
    pgw_sess_t *sess = data;
    uint8_t type = 0;

    ogs_assert(sess);

    type = xact->seq[0].type;

    ogs_debug("GTP Timeout : SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x] "
            "Message-Type[%d]", sess->sgw_s5c_teid, sess->pgw_s5c_teid, type);
}

static uint8_t gtp_cause_from_diameter(
        const uint32_t *dia_err, const uint32_t *dia_exp_err)
{
    if (dia_exp_err) {
    }
    if (dia_err) {
        switch (*dia_err) {
        case OGS_DIAM_UNKNOWN_SESSION_ID:
            return OGS_GTP_CAUSE_APN_ACCESS_DENIED_NO_SUBSCRIPTION;
        }
    }

    ogs_error("Unexpected Diameter Result Code %d/%d, defaulting to severe "
              "network failure",
              dia_err ? *dia_err : -1, dia_exp_err ? *dia_exp_err : -1);
    return OGS_GTP_CAUSE_UE_NOT_AUTHORISED_BY_OCS_OR_EXTERNAL_AAA_SERVER;
}

void pgw_gx_handle_cca_initial_request(
        pgw_sess_t *sess, ogs_diam_gx_message_t *gx_message,
        ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(sess);
    ogs_assert(gx_message);
    ogs_assert(xact);

    ogs_debug("[PGW] Create Session Response");
    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
            sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    if (gx_message->result_code != ER_DIAMETER_SUCCESS) {
        uint8_t cause_value = gtp_cause_from_diameter(
            gx_message->err, gx_message->exp_err);

        ogs_gtp_send_error_message(xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_CREATE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    memset(&h, 0, sizeof(ogs_gtp_header_t));
    h.type = OGS_GTP_CREATE_SESSION_RESPONSE_TYPE;
    h.teid = sess->sgw_s5c_teid;

    pkbuf = pgw_s5c_build_create_session_response(
            h.type, sess, gx_message);
    ogs_expect_or_return(pkbuf);

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    ogs_expect_or_return(rv == OGS_OK);

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    bearer_binding(sess, gx_message);
}

void pgw_gx_handle_cca_termination_request(
        pgw_sess_t *sess, ogs_diam_gx_message_t *gx_message,
        ogs_gtp_xact_t *xact)
{
    int rv;
    ogs_gtp_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    uint32_t sgw_s5c_teid;

    ogs_assert(xact);
    ogs_assert(sess);
    ogs_assert(gx_message);

    /* backup sgw_s5c_teid in session context */
    sgw_s5c_teid = sess->sgw_s5c_teid;

    ogs_debug("[PGW] Delete Session Response");
    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
            sess->sgw_s5c_teid, sess->pgw_s5c_teid);

    /* Remove a pgw session */
    pgw_sess_remove(sess);

    if (gx_message->result_code != ER_DIAMETER_SUCCESS) {
        uint8_t cause_value = gtp_cause_from_diameter(
            gx_message->err, gx_message->exp_err);

        ogs_gtp_send_error_message(xact, sgw_s5c_teid,
                OGS_GTP_DELETE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    memset(&h, 0, sizeof(ogs_gtp_header_t));
    h.type = OGS_GTP_DELETE_SESSION_RESPONSE_TYPE;
    h.teid = sgw_s5c_teid;

    pkbuf = pgw_s5c_build_delete_session_response(
            h.type, sess, gx_message);
    ogs_expect_or_return(pkbuf);

    rv = ogs_gtp_xact_update_tx(xact, &h, pkbuf);
    ogs_expect_or_return(rv == OGS_OK);

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
}

void pgw_gx_handle_re_auth_request(
        pgw_sess_t *sess, ogs_diam_gx_message_t *gx_message)
{
    bearer_binding(sess, gx_message);
}

static void encode_traffic_flow_template(
        ogs_gtp_tft_t *tft, pgw_bearer_t *bearer)
{
    int i, j, len;
    pgw_pf_t *pf = NULL;

    ogs_assert(tft);
    ogs_assert(bearer);

    memset(tft, 0, sizeof(*tft));
    tft->code = OGS_GTP_TFT_CODE_CREATE_NEW_TFT;

    i = 0;
    pf = pgw_pf_first(bearer);
    while (pf) {
        tft->pf[i].direction = pf->direction;
        tft->pf[i].identifier = pf->identifier - 1;
        tft->pf[i].precedence = i+1;

        j = 0, len = 0;
        if (pf->rule.proto) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_PROTOCOL_IDENTIFIER_NEXT_HEADER_TYPE;
            tft->pf[i].component[j].proto = pf->rule.proto;
            j++; len += 2;
        }

        if (pf->rule.ipv4_local) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV4_LOCAL_ADDRESS_TYPE;
            tft->pf[i].component[j].ipv4.addr = pf->rule.ip.local.addr[0];
            tft->pf[i].component[j].ipv4.mask = pf->rule.ip.local.mask[0];
            j++; len += 9;
        }

        if (pf->rule.ipv4_remote) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV4_REMOTE_ADDRESS_TYPE;
            tft->pf[i].component[j].ipv4.addr = pf->rule.ip.remote.addr[0];
            tft->pf[i].component[j].ipv4.mask = pf->rule.ip.remote.mask[0];
            j++; len += 9;
        }

        if (pf->rule.ipv6_local) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV6_LOCAL_ADDRESS_PREFIX_LENGTH_TYPE;
            memcpy(tft->pf[i].component[j].ipv6.addr, pf->rule.ip.local.addr,
                    sizeof pf->rule.ip.local.addr);
            tft->pf[i].component[j].ipv6.prefixlen =
                contigmask((uint8_t *)pf->rule.ip.local.mask, 128);
            j++; len += 18;
        }

        if (pf->rule.ipv6_remote) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV6_REMOTE_ADDRESS_PREFIX_LENGTH_TYPE;
            memcpy(tft->pf[i].component[j].ipv6.addr, pf->rule.ip.remote.addr,
                    sizeof pf->rule.ip.remote.addr);
            tft->pf[i].component[j].ipv6.prefixlen =
                contigmask((uint8_t *)pf->rule.ip.remote.mask, 128);
            j++; len += 18;
        }

        if (pf->rule.port.local.low) {
            if (pf->rule.port.local.low == pf->rule.port.local.high)
            {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_SINGLE_LOCAL_PORT_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.local.low;
                j++; len += 3;
            } else {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_LOCAL_PORT_RANGE_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.local.low;
                tft->pf[i].component[j].port.high = pf->rule.port.local.high;
                j++; len += 5;
            }
        }

        if (pf->rule.port.remote.low) {
            if (pf->rule.port.remote.low == pf->rule.port.remote.high) {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_SINGLE_REMOTE_PORT_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.remote.low;
                j++; len += 3;
            } else {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_REMOTE_PORT_RANGE_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.remote.low;
                tft->pf[i].component[j].port.high = pf->rule.port.remote.high;
                j++; len += 5;
            }
        }

        tft->pf[i].num_of_component = j;
        tft->pf[i].length = len;
        i++;

        pf = pgw_pf_next(pf);
    }
    tft->num_of_packet_filter = i;
}

static void bearer_binding(pgw_sess_t *sess, ogs_diam_gx_message_t *gx_message)
{
    int rv;
    int i, j;

    ogs_assert(sess);
    ogs_assert(gx_message);

    for (i = 0; i < gx_message->num_of_pcc_rule; i++) {
        ogs_gtp_xact_t *xact = NULL;
        ogs_gtp_header_t h;
        ogs_pkbuf_t *pkbuf = NULL;
        pgw_bearer_t *bearer = NULL;

        ogs_pcc_rule_t *pcc_rule = &gx_message->pcc_rule[i];
        int bearer_created = 0;
        int qos_presence = 0;
        ogs_gtp_tft_t tft;

        ogs_assert(pcc_rule);
        if (pcc_rule->name == NULL) {
            ogs_error("No PCC Rule Name");
            continue;
        }

        if (pcc_rule->type == OGS_PCC_RULE_TYPE_INSTALL) {
            bearer = pgw_bearer_find_by_qci_arp(sess, 
                        pcc_rule->qos.qci,
                        pcc_rule->qos.arp.priority_level,
                        pcc_rule->qos.arp.pre_emption_capability,
                        pcc_rule->qos.arp.pre_emption_vulnerability);
            if (!bearer) {
                if (pcc_rule->num_of_flow == 0) {
                    /* TFT is mandatory in
                     * activate dedicated EPS bearer context request */
                    ogs_error("No flow in PCC Rule");
                    continue;
                }

                bearer = pgw_bearer_add(sess);
                ogs_assert(bearer);

                bearer->name = ogs_strdup(pcc_rule->name);
                ogs_assert(bearer->name);

                memcpy(&bearer->qos, &pcc_rule->qos, sizeof(ogs_qos_t));

                bearer_created = 1;
            } else {
                ogs_assert(strcmp(bearer->name, pcc_rule->name) == 0);

                if (pcc_rule->num_of_flow) {
                    /* We'll use always 'Create new TFT'.
                     * Therefore, all previous flows are removed
                     * and replaced by the new flow */
                    pgw_pf_remove_all(bearer);
                }

                if ((pcc_rule->qos.mbr.downlink &&
                    bearer->qos.mbr.downlink != pcc_rule->qos.mbr.downlink) ||
                    (pcc_rule->qos.mbr.uplink &&
                     bearer->qos.mbr.uplink != pcc_rule->qos.mbr.uplink) ||
                    (pcc_rule->qos.gbr.downlink &&
                    bearer->qos.gbr.downlink != pcc_rule->qos.gbr.downlink) ||
                    (pcc_rule->qos.gbr.uplink &&
                    bearer->qos.gbr.uplink != pcc_rule->qos.gbr.uplink)) {
                    /* Update QoS parameter */
                    memcpy(&bearer->qos, &pcc_rule->qos, sizeof(ogs_qos_t));

                    /* Update Bearer Request encodes updated QoS parameter */
                    qos_presence = 1;
                }

                if (pcc_rule->num_of_flow == 0 && qos_presence == 0) {
                    ogs_warn("No need to send 'Update Bearer Request'");
                    ogs_warn("  - Both QoS and TFT are same as before");
                    continue;
                }
            }

            for (j = 0; j < pcc_rule->num_of_flow; j++) {
                ogs_flow_t *flow = &pcc_rule->flow[j];
                pgw_rule_t rule;
                pgw_pf_t *pf = NULL;

                ogs_expect_or_return(flow);
                ogs_expect_or_return(flow->description);

                rv = pgw_compile_packet_filter(&rule, flow->description);
                ogs_expect_or_return(rv == OGS_OK);

                pf = pgw_pf_add(bearer, pcc_rule->precedence);
                ogs_expect_or_return(pf);

                memcpy(&pf->rule, &rule, sizeof(pgw_rule_t));
                pf->direction = flow->direction;
            }
            memset(&tft, 0, sizeof tft);
            if (pcc_rule->num_of_flow)
                encode_traffic_flow_template(&tft, bearer);

            memset(&h, 0, sizeof(ogs_gtp_header_t));
            if (bearer_created == 1) {
                h.type = OGS_GTP_CREATE_BEARER_REQUEST_TYPE;
                h.teid = sess->sgw_s5c_teid;

                /* TFT is mandatory in
                 * activate dedicated EPS bearer context request */
                ogs_assert(pcc_rule->num_of_flow);

                pkbuf = pgw_s5c_build_create_bearer_request(
                        h.type, bearer, pcc_rule->num_of_flow ? &tft : NULL);
                ogs_expect_or_return(pkbuf);
            } else {
                h.type = OGS_GTP_UPDATE_BEARER_REQUEST_TYPE;
                h.teid = sess->sgw_s5c_teid;

                pkbuf = pgw_s5c_build_update_bearer_request(
                        h.type, bearer,
                        OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
                        pcc_rule->num_of_flow ? &tft : NULL, qos_presence);
                ogs_expect_or_return(pkbuf);
            }

            xact = ogs_gtp_xact_local_create(
                    sess->gnode, &h, pkbuf, timeout, sess);
            ogs_expect_or_return(xact);

            rv = ogs_gtp_xact_commit(xact);
            ogs_expect(rv == OGS_OK);
        } else if (pcc_rule->type == OGS_PCC_RULE_TYPE_REMOVE) {
            bearer = pgw_bearer_find_by_name(sess, pcc_rule->name);
            if (!bearer) {
                ogs_warn("No need to send 'Delete Bearer Request'");
                ogs_warn("  - Bearer[Name:%s] has already been removed.",
                        pcc_rule->name);
                return;

            }

            memset(&h, 0, sizeof(ogs_gtp_header_t));
            h.type = OGS_GTP_DELETE_BEARER_REQUEST_TYPE;
            h.teid = sess->sgw_s5c_teid;

            pkbuf = pgw_s5c_build_delete_bearer_request(h.type, bearer,
                    OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED);
            ogs_expect_or_return(pkbuf);

            xact = ogs_gtp_xact_local_create(
                    sess->gnode, &h, pkbuf, timeout, sess);
            ogs_expect_or_return(xact);

            rv = ogs_gtp_xact_commit(xact);
            ogs_expect(rv == OGS_OK);
        } else {
            ogs_error("Invalid Type[%d]", pcc_rule->type);
        }
    }
}

