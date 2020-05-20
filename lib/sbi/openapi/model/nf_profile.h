/*
 * nf_profile.h
 *
 *
 */

#ifndef _OpenAPI_nf_profile_H_
#define _OpenAPI_nf_profile_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "amf_info.h"
#include "ausf_info.h"
#include "bsf_info.h"
#include "chf_info.h"
#include "default_notification_subscription.h"
#include "nf_service.h"
#include "nf_status.h"
#include "nf_type.h"
#include "nrf_info.h"
#include "nwdaf_info.h"
#include "object.h"
#include "pcf_info.h"
#include "plmn_id.h"
#include "plmn_snssai.h"
#include "smf_info.h"
#include "snssai.h"
#include "udm_info.h"
#include "udr_info.h"
#include "upf_info.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_nf_profile_s OpenAPI_nf_profile_t;
typedef struct OpenAPI_nf_profile_s {
    char *nf_instance_id;
    char *nf_instance_name;
    OpenAPI_nf_type_e nf_type;
    OpenAPI_nf_status_e nf_status;
    int heart_beat_timer;
    OpenAPI_list_t *plmn_list;
    OpenAPI_list_t *s_nssais;
    OpenAPI_list_t *per_plmn_snssai_list;
    OpenAPI_list_t *nsi_list;
    char *fqdn;
    char *inter_plmn_fqdn;
    OpenAPI_list_t *ipv4_addresses;
    OpenAPI_list_t *ipv6_addresses;
    OpenAPI_list_t *allowed_plmns;
    OpenAPI_list_t *allowed_nf_types;
    OpenAPI_list_t *allowed_nf_domains;
    OpenAPI_list_t *allowed_nssais;
    int priority;
    int capacity;
    int load;
    char *locality;
    struct OpenAPI_udr_info_s *udr_info;
    OpenAPI_list_t *udr_info_ext;
    struct OpenAPI_udm_info_s *udm_info;
    OpenAPI_list_t *udm_info_ext;
    struct OpenAPI_ausf_info_s *ausf_info;
    OpenAPI_list_t *ausf_info_ext;
    struct OpenAPI_amf_info_s *amf_info;
    OpenAPI_list_t *amf_info_ext;
    struct OpenAPI_smf_info_s *smf_info;
    OpenAPI_list_t *smf_info_ext;
    struct OpenAPI_upf_info_s *upf_info;
    OpenAPI_list_t *upf_info_ext;
    struct OpenAPI_pcf_info_s *pcf_info;
    OpenAPI_list_t *pcf_info_ext;
    struct OpenAPI_bsf_info_s *bsf_info;
    OpenAPI_list_t *bsf_info_ext;
    struct OpenAPI_chf_info_s *chf_info;
    OpenAPI_list_t *chf_info_ext;
    struct OpenAPI_nrf_info_s *nrf_info;
    struct OpenAPI_nwdaf_info_s *nwdaf_info;
    OpenAPI_object_t *custom_info;
    char *recovery_time;
    int nf_service_persistence;
    OpenAPI_list_t *nf_services;
    int nf_profile_changes_support_ind;
    int nf_profile_changes_ind;
    OpenAPI_list_t *default_notification_subscriptions;
} OpenAPI_nf_profile_t;

OpenAPI_nf_profile_t *OpenAPI_nf_profile_create(
    char *nf_instance_id,
    char *nf_instance_name,
    OpenAPI_nf_type_e nf_type,
    OpenAPI_nf_status_e nf_status,
    int heart_beat_timer,
    OpenAPI_list_t *plmn_list,
    OpenAPI_list_t *s_nssais,
    OpenAPI_list_t *per_plmn_snssai_list,
    OpenAPI_list_t *nsi_list,
    char *fqdn,
    char *inter_plmn_fqdn,
    OpenAPI_list_t *ipv4_addresses,
    OpenAPI_list_t *ipv6_addresses,
    OpenAPI_list_t *allowed_plmns,
    OpenAPI_list_t *allowed_nf_types,
    OpenAPI_list_t *allowed_nf_domains,
    OpenAPI_list_t *allowed_nssais,
    int priority,
    int capacity,
    int load,
    char *locality,
    OpenAPI_udr_info_t *udr_info,
    OpenAPI_list_t *udr_info_ext,
    OpenAPI_udm_info_t *udm_info,
    OpenAPI_list_t *udm_info_ext,
    OpenAPI_ausf_info_t *ausf_info,
    OpenAPI_list_t *ausf_info_ext,
    OpenAPI_amf_info_t *amf_info,
    OpenAPI_list_t *amf_info_ext,
    OpenAPI_smf_info_t *smf_info,
    OpenAPI_list_t *smf_info_ext,
    OpenAPI_upf_info_t *upf_info,
    OpenAPI_list_t *upf_info_ext,
    OpenAPI_pcf_info_t *pcf_info,
    OpenAPI_list_t *pcf_info_ext,
    OpenAPI_bsf_info_t *bsf_info,
    OpenAPI_list_t *bsf_info_ext,
    OpenAPI_chf_info_t *chf_info,
    OpenAPI_list_t *chf_info_ext,
    OpenAPI_nrf_info_t *nrf_info,
    OpenAPI_nwdaf_info_t *nwdaf_info,
    OpenAPI_object_t *custom_info,
    char *recovery_time,
    int nf_service_persistence,
    OpenAPI_list_t *nf_services,
    int nf_profile_changes_support_ind,
    int nf_profile_changes_ind,
    OpenAPI_list_t *default_notification_subscriptions
    );
void OpenAPI_nf_profile_free(OpenAPI_nf_profile_t *nf_profile);
OpenAPI_nf_profile_t *OpenAPI_nf_profile_parseFromJSON(cJSON *nf_profileJSON);
cJSON *OpenAPI_nf_profile_convertToJSON(OpenAPI_nf_profile_t *nf_profile);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_nf_profile_H_ */

