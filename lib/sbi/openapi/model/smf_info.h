/*
 * smf_info.h
 *
 *
 */

#ifndef _OpenAPI_smf_info_H_
#define _OpenAPI_smf_info_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "access_type.h"
#include "snssai_smf_info_item.h"
#include "tai.h"
#include "tai_range.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_smf_info_s OpenAPI_smf_info_t;
typedef struct OpenAPI_smf_info_s {
    OpenAPI_list_t *s_nssai_smf_info_list;
    OpenAPI_list_t *tai_list;
    OpenAPI_list_t *tai_range_list;
    char *pgw_fqdn;
    OpenAPI_list_t *access_type;
} OpenAPI_smf_info_t;

OpenAPI_smf_info_t *OpenAPI_smf_info_create(
    OpenAPI_list_t *s_nssai_smf_info_list,
    OpenAPI_list_t *tai_list,
    OpenAPI_list_t *tai_range_list,
    char *pgw_fqdn,
    OpenAPI_list_t *access_type
    );
void OpenAPI_smf_info_free(OpenAPI_smf_info_t *smf_info);
OpenAPI_smf_info_t *OpenAPI_smf_info_parseFromJSON(cJSON *smf_infoJSON);
cJSON *OpenAPI_smf_info_convertToJSON(OpenAPI_smf_info_t *smf_info);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_smf_info_H_ */

