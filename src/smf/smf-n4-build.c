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

#include "smf-context.h"
#include "smf-n4-build.h"

ogs_pkbuf_t *smf_n4_build_association_setup_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_request_t *req = NULL;

    ogs_pfcp_node_id_t node_id;
    uint32_t recovery_time_stamp = 11; 
    uint8_t cp_function_features = 0;

    ogs_debug("[SMF] Association Setup Request");

    req = &pfcp_message.pfcp_association_setup_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    /* Set node id, mandatory */
    memset(&node_id, 0, sizeof node_id);
    node_id.type = OGS_PFCP_NODE_ID_IPV4;
    node_id.addr = 0x01020304;
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = 5;
    
    /* Set Recovery Time Stamp, mandatory */
    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.data = &recovery_time_stamp;
    req->recovery_time_stamp.len = sizeof recovery_time_stamp;

    /* Set CP Function Features, conditional */
    req->cp_function_features.presence = 1;
    req->cp_function_features.data = &cp_function_features;
    req->cp_function_features.len = sizeof cp_function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}
