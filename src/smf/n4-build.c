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
            smf_self()->pfcp_addr, smf_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;
    
    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = smf_self()->pfcp_started;

    req->cp_function_features.presence = 1;
    req->cp_function_features.u8 = smf_self()->cp_function_features;

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
            smf_self()->pfcp_addr, smf_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    rsp->node_id.presence = 1;
    rsp->node_id.data = &node_id;
    rsp->node_id.len = node_id_len;

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;
    
    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = smf_self()->pfcp_started;

    rsp->cp_function_features.presence = 1;
    rsp->cp_function_features.u8 = smf_self()->cp_function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_heartbeat_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_heartbeat_request_t *req = NULL;

    ogs_debug("[SMF] Heartbeat Request");

    req = &pfcp_message.pfcp_heartbeat_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = smf_self()->pfcp_started;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_heartbeat_response(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_heartbeat_response_t *rsp = NULL;

    ogs_debug("[SMF] Heartbeat Response");

    rsp = &pfcp_message.pfcp_heartbeat_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = smf_self()->pfcp_started;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *smf_n4_build_session_establishment_request(
        uint8_t type, smf_sess_t *sess)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_session_establishment_request_t *req = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;
    ogs_pfcp_f_seid_t f_seid;
    int f_seid_len = 0;

    ogs_debug("[SMF] Session Establishment Request");

    req = &pfcp_message.pfcp_session_establishment_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            smf_self()->pfcp_addr, smf_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;

    ogs_pfcp_sockaddr_to_f_seid(
            smf_self()->pfcp_addr, smf_self()->pfcp_addr6,
            &f_seid, &f_seid_len);
    req->cp_f_seid.presence = 1;
    req->cp_f_seid.data = &f_seid;
    req->cp_f_seid.len = f_seid_len;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}
