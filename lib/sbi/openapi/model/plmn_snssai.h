/*
 * plmn_snssai.h
 *
 *
 */

#ifndef _OpenAPI_plmn_snssai_H_
#define _OpenAPI_plmn_snssai_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "plmn_id.h"
#include "snssai.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_plmn_snssai_s OpenAPI_plmn_snssai_t;
typedef struct OpenAPI_plmn_snssai_s {
    struct OpenAPI_plmn_id_s *plmn_id;
    OpenAPI_list_t *s_nssai_list;
} OpenAPI_plmn_snssai_t;

OpenAPI_plmn_snssai_t *OpenAPI_plmn_snssai_create(
    OpenAPI_plmn_id_t *plmn_id,
    OpenAPI_list_t *s_nssai_list
    );
void OpenAPI_plmn_snssai_free(OpenAPI_plmn_snssai_t *plmn_snssai);
OpenAPI_plmn_snssai_t *OpenAPI_plmn_snssai_parseFromJSON(cJSON *plmn_snssaiJSON);
cJSON *OpenAPI_plmn_snssai_convertToJSON(OpenAPI_plmn_snssai_t *plmn_snssai);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_plmn_snssai_H_ */

