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

#ifndef OGS_PFCP_TYPES_H
#define OGS_PFCP_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_PFCP_VERSION                                    1

#define OGS_PFCP_CAUSE_REQUEST_ACCEPTED                     1
#define OGS_PFCP_CAUSE_REQUEST_REJECTED                     64
#define OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND            65
#define OGS_PFCP_CAUSE_MANDATORY_IE_MISSING                 66
#define OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING               67
#define OGS_PFCP_CAUSE_INVALID_LENGTH                       68
#define OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT               69
#define OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY            70
#define OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION     71
#define OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION      72
#define OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE   73
#define OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION            74
#define OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE               75
#define OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED                76
#define OGS_PFCP_CAUSE_SYSTEM_FAILURE                       77

const char *ogs_pfcp_cause_get_name(uint8_t cause);

/*
 * 8.2.2 Source Interface
 * NOTE 1: The "Access" and "Core" values denote an uplink and downlink
 * traffic direction respectively.
 * NOTE 2: For indirect data forwarding, the Source Interface in the PDR and
 * the Destination Interface in the FAR shall both be set to "Access",
 * in the forwarding SGW(s). The Interface value does not infer any
 * traffic direction, in PDRs and FARs set up for indirect data
 * forwarding, i.e. with both the Source and Destination Interfaces set
 * to Access.
 *
 * 8.2.24 Destination Interface
 * NOTE 1: The "Access" and "Core" values denote a downlink and uplink
 * traffic direction respectively.
 * NOTE 2: LI Function may denote an SX3LIF or an LMISF. See clause 5.7.
 * NOTE 3: For indirect data forwarding, the Source Interface in the PDR and
 * the Destination Interface in the FAR shall both be set to "Access",
 * in the forwarding SGW(s). The Interface value does not infer any
 * traffic direction, in PDRs and FARs set up for indirect data
 * forwarding, i.e. with both the Source and Destination Interfaces set
 * to Access.
 * NOTE 4: For a HTTP redirection, the Source Interface in the PDR to match
 * the uplink packets to be redirected and the Destination Interface in
 * the FAR to enable the HTTP redirection shall both be set to "Access".
 */
#define OGS_PFCP_INTERFACE_ACCESS                           0
#define OGS_PFCP_INTERFACE_CORE                             1
#define OGS_PFCP_INTERFACE_SGI_N6_LAN                       2
#define OGS_PFCP_INTERFACE_CP_FUNCTION                      3
#define OGS_PFCP_INTERFACE_LI_FUNCTION                      4

/* 
 * 8.2.26 Apply Action
 *
 * Bit 1 – DROP (Drop): when set to 1, this indicates a request
 * to drop the packets.
 * Bit 2 – FORW (Forward): when set to 1, this indicates a request
 * to forward the packets.
 * Bit 3 – BUFF (Buffer): when set to 1, this indicates a request
 * to buffer the packets.
 * Bit 4 – NOCP (Notify the CP function): when set to 1,
 * this indicates a request to notify the CP function about the
 * arrival of a first downlink packet being buffered.
 * Bit 5 – DUPL (Duplicate): when set to 1, this indicates a request
 * to duplicate the packets.
 * Bit 6 to 8 – Spare, for future use and set to 0.
 *
 * One and only one of the DROP, FORW and BUFF flags shall be set to 1.
 * The NOCP flag may only be set if the BUFF flag is set.
 * The DUPL flag may be set with any of the DROP, FORW, BUFF and NOCP flags.
 */
#define OGS_PFCP_APPLY_ACTION_DROP                          1
#define OGS_PFCP_APPLY_ACTION_FORW                          2
#define OGS_PFCP_APPLY_ACTION_BUFF                          4
#define OGS_PFCP_APPLY_ACTION_NOCP                          8
#define OGS_PFCP_APPLY_ACTION_DUPL                          16

#define OGS_PFCP_PDN_TYPE_IPV4                              1
#define OGS_PFCP_PDN_TYPE_IPV6                              2
#define OGS_PFCP_PDN_TYPE_IPV4V6                            3
#define OGS_PFCP_PDN_TYPE_NONIP                             4

#define OGS_PFCP_UE_IP_ADDR_HDR_LEN                         1
#define OGS_PFCP_UE_IP_ADDR_IPV4_LEN  \
    OGS_IPV4_LEN + OGS_PFCP_UE_IP_ADDR_HDR_LEN
#define OGS_PFCP_UE_IP_ADDR_IPV6_LEN  \
    OGS_IPV6_LEN + OGS_PFCP_UE_IP_ADDR_HDR_LEN
#define OGS_PFCP_UE_IP_ADDR_IPV4V6_LEN \
    OGS_IPV4V6_LEN + OGS_PFCP_UE_IP_ADDR_HDR_LEN

typedef struct ogs_pfcp_ue_ip_addr_s {
ED4(uint8_t       spare:5;,
    uint8_t       sd:1;,  /* source or destination*/
    uint8_t       ipv4:1;,
    uint8_t       ipv6:1;)
    union {
        uint32_t addr;
        uint8_t addr6[OGS_IPV6_LEN];
        struct {
            uint32_t addr;
            uint8_t addr6[OGS_IPV6_LEN];
        } both;
    };
} __attribute__ ((packed)) ogs_pfcp_ue_ip_addr_t;

typedef struct ogs_pfcp_f_teid_s {
ED5(uint8_t       spare:4;,
    uint8_t       chid:1;,
    uint8_t       ch:1;,
    uint8_t       ipv6:1;,
    uint8_t       ipv4:1;)
    uint32_t      teid;
    union {
        union {
            uint32_t addr;
            uint8_t addr6[OGS_IPV6_LEN];
            struct {
                uint32_t addr;
                uint8_t addr6[OGS_IPV6_LEN];
            } both;
        };
        uint8_t choose_id;
    };
} __attribute__ ((packed)) ogs_pfcp_f_teid_t;

typedef struct ogs_pfcp_f_seid_s {
ED3(uint8_t       spare:6;,
    uint8_t       ipv4:1;,
    uint8_t       ipv6:1;)
    uint64_t      seid;
    union {
        uint32_t addr;
        uint8_t addr6[OGS_IPV6_LEN];
        struct {
            uint32_t addr;
            uint8_t addr6[OGS_IPV6_LEN];
        } both;
    };
} __attribute__ ((packed)) ogs_pfcp_f_seid_t;

#define OGS_PFCP_NODE_ID_IPV4   0
#define OGS_PFCP_NODE_ID_IPV6   1
#define OGS_PFCP_NODE_ID_FQDN   2
typedef struct ogs_pfcp_node_id_s {
ED2(uint8_t spare:4;,
    uint8_t type:4;)
    union {
        uint32_t addr;
        uint8_t addr6[OGS_IPV6_LEN];
        char fqdn[OGS_MAX_FQDN_LEN];
    };
} __attribute__ ((packed)) ogs_pfcp_node_id_t;

typedef struct ogs_pfcp_outer_hdr_s {
ED5(uint8_t       spare:4;,
    uint8_t       udp_ipv6:1;,
    uint8_t       udp_ipv4:1;,
    uint8_t       gtpu_ipv6:1;,
    uint8_t       gtpu_ipv4:1;)
    uint8_t       void0;
    uint32_t      teid;
    union {
        uint32_t addr;
        uint8_t addr6[OGS_IPV6_LEN];
        struct {
            uint32_t addr;
            uint8_t addr6[OGS_IPV6_LEN];
        } both;
    };
} __attribute__ ((packed)) ogs_pfcp_outer_hdr_t;

typedef struct ogs_pfcp_report_type_s {
ED5(uint8_t       spare0:4;,
    uint8_t       upir:1;,      /* User Plane Inactivity Report */
    uint8_t       erir:1;,      /* Error Indication Report */
    uint8_t       usar:1;,      /* Usage Report */
    uint8_t       dldr:1;)      /* Downlink Data Report */
} __attribute__ ((packed)) pfcp_report_type_t;

typedef struct ogs_pfcp_downlink_data_service_information_s {
#define OGS_PFCP_DOWNLINK_DATA_SERVICE_INFORMATION_LEN(__data) \
    (sizeof(struct _pfcp_downlink_data_service_information_t) - \
        (__data).ppi - (__data).qfii)
ED3(uint8_t       spare1:6;,
    uint8_t       ppi:1;,       /* Paging Policy Indication */
    uint8_t       qfii:1;)
ED2(
    uint8_t       spare2:2;,
    uint8_t       paging_policy_indication:6;
)
ED2(
    uint8_t       spare:2;,
    uint8_t       QFI:6;
)
} __attribute__ ((packed)) ogs_pfcp_downlink_data_service_information_t;

typedef struct ogs_pfcp_user_plane_ip_resource_information_s {
ED6(uint8_t       spare1:1;,
    uint8_t       assosi:1;,
    uint8_t       assoni:1;,
    uint8_t       teidri:3;,
    uint8_t       v6:1;,
    uint8_t       v4:1;)

    uint8_t       teid_range:8;
    uint32_t      addr;
    uint8_t       addr6[OGS_IPV6_LEN];
    uint8_t       network_instance;
ED2(uint8_t       spare2:4;,
    uint8_t       source_interface:4;
)
} __attribute__ ((packed)) ogs_pfcp_user_plane_ip_resource_information_t;

#ifdef __cplusplus
}
#endif

#endif /* OGS_PFCP_TYPES_H */

