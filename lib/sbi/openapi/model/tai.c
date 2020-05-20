
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tai.h"

OpenAPI_tai_t *OpenAPI_tai_create(
    OpenAPI_plmn_id_t *plmn_id,
    char *tac
    )
{
    OpenAPI_tai_t *tai_local_var = OpenAPI_malloc(sizeof(OpenAPI_tai_t));
    if (!tai_local_var) {
        return NULL;
    }
    tai_local_var->plmn_id = plmn_id;
    tai_local_var->tac = tac;

    return tai_local_var;
}

void OpenAPI_tai_free(OpenAPI_tai_t *tai)
{
    if (NULL == tai) {
        return;
    }
    OpenAPI_lnode_t *node;
    OpenAPI_plmn_id_free(tai->plmn_id);
    ogs_free(tai->tac);
    ogs_free(tai);
}

cJSON *OpenAPI_tai_convertToJSON(OpenAPI_tai_t *tai)
{
    cJSON *item = NULL;

    if (tai == NULL) {
        ogs_error("OpenAPI_tai_convertToJSON() failed [Tai]");
        return NULL;
    }

    item = cJSON_CreateObject();
    if (!tai->plmn_id) {
        ogs_error("OpenAPI_tai_convertToJSON() failed [plmn_id]");
        goto end;
    }
    cJSON *plmn_id_local_JSON = OpenAPI_plmn_id_convertToJSON(tai->plmn_id);
    if (plmn_id_local_JSON == NULL) {
        ogs_error("OpenAPI_tai_convertToJSON() failed [plmn_id]");
        goto end;
    }
    cJSON_AddItemToObject(item, "plmnId", plmn_id_local_JSON);
    if (item->child == NULL) {
        ogs_error("OpenAPI_tai_convertToJSON() failed [plmn_id]");
        goto end;
    }

    if (!tai->tac) {
        ogs_error("OpenAPI_tai_convertToJSON() failed [tac]");
        goto end;
    }
    if (cJSON_AddStringToObject(item, "tac", tai->tac) == NULL) {
        ogs_error("OpenAPI_tai_convertToJSON() failed [tac]");
        goto end;
    }

end:
    return item;
}

OpenAPI_tai_t *OpenAPI_tai_parseFromJSON(cJSON *taiJSON)
{
    OpenAPI_tai_t *tai_local_var = NULL;
    cJSON *plmn_id = cJSON_GetObjectItemCaseSensitive(taiJSON, "plmnId");
    if (!plmn_id) {
        ogs_error("OpenAPI_tai_parseFromJSON() failed [plmn_id]");
        goto end;
    }

    OpenAPI_plmn_id_t *plmn_id_local_nonprim = NULL;

    plmn_id_local_nonprim = OpenAPI_plmn_id_parseFromJSON(plmn_id);

    cJSON *tac = cJSON_GetObjectItemCaseSensitive(taiJSON, "tac");
    if (!tac) {
        ogs_error("OpenAPI_tai_parseFromJSON() failed [tac]");
        goto end;
    }


    if (!cJSON_IsString(tac)) {
        ogs_error("OpenAPI_tai_parseFromJSON() failed [tac]");
        goto end;
    }

    tai_local_var = OpenAPI_tai_create (
        plmn_id_local_nonprim,
        ogs_strdup(tac->valuestring)
        );

    return tai_local_var;
end:
    return NULL;
}

