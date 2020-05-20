/*
 * upf_info.h
 *
 *
 */

#ifndef _OpenAPI_upf_info_H_
#define _OpenAPI_upf_info_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "atsss_capability.h"
#include "interface_upf_info_item.h"
#include "pdu_session_type.h"
#include "snssai_upf_info_item.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_upf_info_s OpenAPI_upf_info_t;
typedef struct OpenAPI_upf_info_s {
    OpenAPI_list_t *s_nssai_upf_info_list;
    OpenAPI_list_t *smf_serving_area;
    OpenAPI_list_t *interface_upf_info_list;
    int iwk_eps_ind;
    OpenAPI_list_t *pdu_session_types;
    struct OpenAPI_atsss_capability_s *atsss_capability;
    int ue_ip_addr_ind;
} OpenAPI_upf_info_t;

OpenAPI_upf_info_t *OpenAPI_upf_info_create(
    OpenAPI_list_t *s_nssai_upf_info_list,
    OpenAPI_list_t *smf_serving_area,
    OpenAPI_list_t *interface_upf_info_list,
    int iwk_eps_ind,
    OpenAPI_list_t *pdu_session_types,
    OpenAPI_atsss_capability_t *atsss_capability,
    int ue_ip_addr_ind
    );
void OpenAPI_upf_info_free(OpenAPI_upf_info_t *upf_info);
OpenAPI_upf_info_t *OpenAPI_upf_info_parseFromJSON(cJSON *upf_infoJSON);
cJSON *OpenAPI_upf_info_convertToJSON(OpenAPI_upf_info_t *upf_info);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_upf_info_H_ */

