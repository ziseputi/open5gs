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
#include "n4-build.h"

ogs_pkbuf_t *smf_n4_build_association_setup_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_request_t *req = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_debug("[SMF] Association Setup Request");

    req = &pfcp_message.pfcp_association_setup_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;
    
    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    req->cp_function_features.presence = 1;
    req->cp_function_features.u8 = smf_self()->function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_association_setup_response(uint8_t type,
        uint8_t cause)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_response_t *rsp = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_debug("[SMF] Association Setup Response");

    rsp = &pfcp_message.pfcp_association_setup_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    rsp->node_id.presence = 1;
    rsp->node_id.data = &node_id;
    rsp->node_id.len = node_id_len;

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;
    
    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    rsp->cp_function_features.presence = 1;
    rsp->cp_function_features.u8 = smf_self()->function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_session_establishment_request(
        uint8_t type, smf_sess_t *sess)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_session_establishment_request_t *req = NULL;
    ogs_pfcp_tlv_create_pdr_t *create_pdrs[OGS_MAX_NUM_OF_PDR];
    ogs_pfcp_tlv_create_far_t *create_fars[OGS_MAX_NUM_OF_FAR];
    ogs_pfcp_tlv_create_urr_t *create_urrs[OGS_MAX_NUM_OF_URR];
    ogs_pfcp_tlv_create_qer_t *create_qers[OGS_MAX_NUM_OF_QER];

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_qer_t *qer = NULL;
    int i;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;
    ogs_pfcp_f_seid_t f_seid;
    int f_seid_len = 0;

    ogs_debug("[SMF] Session Establishment Request");
    ogs_assert(sess);

    req = &pfcp_message.pfcp_session_establishment_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    /* Node ID */
    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;

    /* F-SEID */
    ogs_pfcp_sockaddr_to_f_seid(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            &f_seid, &f_seid_len);
    f_seid.seid = htobe64(sess->pfcp.local_n4_seid);
    req->cp_f_seid.presence = 1;
    req->cp_f_seid.data = &f_seid;
    req->cp_f_seid.len = f_seid_len;

    /* Create PDR */
    ogs_pfcp_create_pdrs_in_session_establishment(&create_pdrs, req);
    i = 0;
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        ogs_pfcp_tlv_create_pdr_t *message = create_pdrs[i];
        ogs_pfcp_pdr_t *context = pdr;
        int j = 0;

        ogs_assert(message);
        ogs_assert(pdr);

        message->presence = 1;
        message->pdr_id.presence = 1;
        message->pdr_id.u16 = context->id;

        message->precedence.presence = 1;
        message->precedence.u32 = context->precedence;

        message->pdi.presence = 1;
        message->pdi.source_interface.presence = 1;
        message->pdi.source_interface.u8 = context->src_if;

        if (context->f_teid_len) {
            message->pdi.local_f_teid.presence = 1;
            message->pdi.local_f_teid.data = &context->f_teid;
            message->pdi.local_f_teid.len = context->f_teid_len;
        }

        message->pdi.network_instance.presence = 1;
        message->pdi.network_instance.len = ogs_fqdn_build(
                    context->apn, sess->pdn.apn, strlen(sess->pdn.apn));
        message->pdi.network_instance.data = context->apn;

        if (sess->pdn.paa.pdn_type == OGS_GTP_PDN_TYPE_IPV4) {
        } else if (sess->pdn.paa.pdn_type == OGS_GTP_PDN_TYPE_IPV6) {
        } else if (sess->pdn.paa.pdn_type == OGS_GTP_PDN_TYPE_IPV4V6) {
        }
        message->pdi.ue_ip_address.presence = 1;
        message->pdi.ue_ip_address.data = &context->ue_ip_addr;
        message->pdi.ue_ip_address.len = context->ue_ip_addr_len;

        if (pdr->far) {
            message->far_id.presence = 1;
            message->far_id.u32 = pdr->far->id;
        }

        for (j = 0; j < pdr->num_of_urr; j++) {
            if (j == 0) {
                message->urr_id.presence = 1;
                ogs_assert(pdr->urrs[j]);
                message->urr_id.u32 = pdr->urrs[j]->id;
            } else {
                ogs_error("[%d] No support multiple URR", j);
            }
        }
        for (j = 0; j < pdr->num_of_qer; j++) {
            if (j == 0) {
                message->qer_id.presence = 1;
                ogs_assert(pdr->qers[j]);
                message->qer_id.u32 = pdr->qers[j]->id;
            } else {
                ogs_error("[%d] No support multiple QER", j);
            }
        }

        i++;
    }

    /* Create FAR */
    ogs_pfcp_create_fars_in_session_establishment(&create_fars, req);
    i = 0;
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        ogs_pfcp_tlv_create_far_t *message = create_fars[i];
        ogs_pfcp_far_t *context = far;

        ogs_assert(message);
        ogs_assert(far);

        message->presence = 1;
        message->far_id.presence = 1;
        message->far_id.u32 = context->id;

        message->apply_action.presence = 1;
        message->apply_action.u8 = context->apply_action;

        message->forwarding_parameters.presence = 1;
        message->forwarding_parameters.destination_interface.presence = 1;
        message->forwarding_parameters.destination_interface.u8 =
            context->dst_if;

        i++;
    }

    /* Create URR */
    ogs_pfcp_create_urrs_in_session_establishment(&create_urrs, req);
    i = 0;
    ogs_list_for_each(&sess->pfcp.urr_list, urr) {
        ogs_pfcp_tlv_create_urr_t *message = create_urrs[i];
        ogs_pfcp_urr_t *context = urr;

        ogs_assert(message);
        ogs_assert(urr);

        message->presence = 1;
        message->urr_id.presence = 1;
        message->urr_id.u32 = context->id;

        i++;
    }

    /* Create QER */
    ogs_pfcp_create_qers_in_session_establishment(&create_qers, req);
    i = 0;
    ogs_list_for_each(&sess->pfcp.qer_list, qer) {
        ogs_pfcp_tlv_create_qer_t *message = create_qers[i];
        ogs_pfcp_qer_t *context = qer;

        ogs_assert(message);
        ogs_assert(qer);

        message->presence = 1;
        message->qer_id.presence = 1;
        message->qer_id.u32 = context->id;

        i++;
    }

    /* PDN Type */
    req->pdn_type.presence = 1;
    req->pdn_type.u8 = sess->pdn.paa.pdn_type;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}
