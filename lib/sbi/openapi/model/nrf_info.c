
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "nrf_info.h"

OpenAPI_nrf_info_t *OpenAPI_nrf_info_create(
    OpenAPI_list_t* served_udr_info,
    OpenAPI_list_t* served_udm_info,
    OpenAPI_list_t* served_ausf_info,
    OpenAPI_list_t* served_amf_info,
    OpenAPI_list_t* served_smf_info,
    OpenAPI_list_t* served_upf_info,
    OpenAPI_list_t* served_pcf_info,
    OpenAPI_list_t* served_bsf_info,
    OpenAPI_list_t* served_chf_info,
    OpenAPI_list_t* served_nwdaf_info
    )
{
    OpenAPI_nrf_info_t *nrf_info_local_var = OpenAPI_malloc(sizeof(OpenAPI_nrf_info_t));
    if (!nrf_info_local_var) {
        return NULL;
    }
    nrf_info_local_var->served_udr_info = served_udr_info;
    nrf_info_local_var->served_udm_info = served_udm_info;
    nrf_info_local_var->served_ausf_info = served_ausf_info;
    nrf_info_local_var->served_amf_info = served_amf_info;
    nrf_info_local_var->served_smf_info = served_smf_info;
    nrf_info_local_var->served_upf_info = served_upf_info;
    nrf_info_local_var->served_pcf_info = served_pcf_info;
    nrf_info_local_var->served_bsf_info = served_bsf_info;
    nrf_info_local_var->served_chf_info = served_chf_info;
    nrf_info_local_var->served_nwdaf_info = served_nwdaf_info;

    return nrf_info_local_var;
}

void OpenAPI_nrf_info_free(OpenAPI_nrf_info_t *nrf_info)
{
    if (NULL == nrf_info) {
        return;
    }
    OpenAPI_lnode_t *node;
    OpenAPI_list_for_each(nrf_info->served_udr_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_udr_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_udr_info);
    OpenAPI_list_for_each(nrf_info->served_udm_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_udm_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_udm_info);
    OpenAPI_list_for_each(nrf_info->served_ausf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_ausf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_ausf_info);
    OpenAPI_list_for_each(nrf_info->served_amf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_amf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_amf_info);
    OpenAPI_list_for_each(nrf_info->served_smf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_smf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_smf_info);
    OpenAPI_list_for_each(nrf_info->served_upf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_upf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_upf_info);
    OpenAPI_list_for_each(nrf_info->served_pcf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_pcf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_pcf_info);
    OpenAPI_list_for_each(nrf_info->served_bsf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_bsf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_bsf_info);
    OpenAPI_list_for_each(nrf_info->served_chf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_chf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_chf_info);
    OpenAPI_list_for_each(nrf_info->served_nwdaf_info, node) {
        OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)node->data;
        OpenAPI_nwdaf_info_free(localKeyValue->value);
        ogs_free(localKeyValue);
    }
    OpenAPI_list_free(nrf_info->served_nwdaf_info);
    ogs_free(nrf_info);
}

cJSON *OpenAPI_nrf_info_convertToJSON(OpenAPI_nrf_info_t *nrf_info)
{
    cJSON *item = NULL;

    if (nrf_info == NULL) {
        ogs_error("OpenAPI_nrf_info_convertToJSON() failed [NrfInfo]");
        return NULL;
    }

    item = cJSON_CreateObject();
    if (nrf_info->served_udr_info) {
        cJSON *served_udr_info = cJSON_AddObjectToObject(item, "servedUdrInfo");
        if (served_udr_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_udr_info]");
            goto end;
        }
        cJSON *localMapObject = served_udr_info;
        OpenAPI_lnode_t *served_udr_info_node;
        if (nrf_info->served_udr_info) {
            OpenAPI_list_for_each(nrf_info->served_udr_info, served_udr_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_udr_info_node->data;
                cJSON *itemLocal = OpenAPI_udr_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_udr_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_udr_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_udm_info) {
        cJSON *served_udm_info = cJSON_AddObjectToObject(item, "servedUdmInfo");
        if (served_udm_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_udm_info]");
            goto end;
        }
        cJSON *localMapObject = served_udm_info;
        OpenAPI_lnode_t *served_udm_info_node;
        if (nrf_info->served_udm_info) {
            OpenAPI_list_for_each(nrf_info->served_udm_info, served_udm_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_udm_info_node->data;
                cJSON *itemLocal = OpenAPI_udm_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_udm_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_udm_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_ausf_info) {
        cJSON *served_ausf_info = cJSON_AddObjectToObject(item, "servedAusfInfo");
        if (served_ausf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_ausf_info]");
            goto end;
        }
        cJSON *localMapObject = served_ausf_info;
        OpenAPI_lnode_t *served_ausf_info_node;
        if (nrf_info->served_ausf_info) {
            OpenAPI_list_for_each(nrf_info->served_ausf_info, served_ausf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_ausf_info_node->data;
                cJSON *itemLocal = OpenAPI_ausf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_ausf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_ausf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_amf_info) {
        cJSON *served_amf_info = cJSON_AddObjectToObject(item, "servedAmfInfo");
        if (served_amf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_amf_info]");
            goto end;
        }
        cJSON *localMapObject = served_amf_info;
        OpenAPI_lnode_t *served_amf_info_node;
        if (nrf_info->served_amf_info) {
            OpenAPI_list_for_each(nrf_info->served_amf_info, served_amf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_amf_info_node->data;
                cJSON *itemLocal = OpenAPI_amf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_amf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_amf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_smf_info) {
        cJSON *served_smf_info = cJSON_AddObjectToObject(item, "servedSmfInfo");
        if (served_smf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_smf_info]");
            goto end;
        }
        cJSON *localMapObject = served_smf_info;
        OpenAPI_lnode_t *served_smf_info_node;
        if (nrf_info->served_smf_info) {
            OpenAPI_list_for_each(nrf_info->served_smf_info, served_smf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_smf_info_node->data;
                cJSON *itemLocal = OpenAPI_smf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_smf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_smf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_upf_info) {
        cJSON *served_upf_info = cJSON_AddObjectToObject(item, "servedUpfInfo");
        if (served_upf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_upf_info]");
            goto end;
        }
        cJSON *localMapObject = served_upf_info;
        OpenAPI_lnode_t *served_upf_info_node;
        if (nrf_info->served_upf_info) {
            OpenAPI_list_for_each(nrf_info->served_upf_info, served_upf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_upf_info_node->data;
                cJSON *itemLocal = OpenAPI_upf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_upf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_upf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_pcf_info) {
        cJSON *served_pcf_info = cJSON_AddObjectToObject(item, "servedPcfInfo");
        if (served_pcf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_pcf_info]");
            goto end;
        }
        cJSON *localMapObject = served_pcf_info;
        OpenAPI_lnode_t *served_pcf_info_node;
        if (nrf_info->served_pcf_info) {
            OpenAPI_list_for_each(nrf_info->served_pcf_info, served_pcf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_pcf_info_node->data;
                cJSON *itemLocal = OpenAPI_pcf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_pcf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_pcf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_bsf_info) {
        cJSON *served_bsf_info = cJSON_AddObjectToObject(item, "servedBsfInfo");
        if (served_bsf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_bsf_info]");
            goto end;
        }
        cJSON *localMapObject = served_bsf_info;
        OpenAPI_lnode_t *served_bsf_info_node;
        if (nrf_info->served_bsf_info) {
            OpenAPI_list_for_each(nrf_info->served_bsf_info, served_bsf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_bsf_info_node->data;
                cJSON *itemLocal = OpenAPI_bsf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_bsf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_bsf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_chf_info) {
        cJSON *served_chf_info = cJSON_AddObjectToObject(item, "servedChfInfo");
        if (served_chf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_chf_info]");
            goto end;
        }
        cJSON *localMapObject = served_chf_info;
        OpenAPI_lnode_t *served_chf_info_node;
        if (nrf_info->served_chf_info) {
            OpenAPI_list_for_each(nrf_info->served_chf_info, served_chf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_chf_info_node->data;
                cJSON *itemLocal = OpenAPI_chf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_chf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_chf_info, localKeyValue->key, itemLocal);
            }
        }
    }

    if (nrf_info->served_nwdaf_info) {
        cJSON *served_nwdaf_info = cJSON_AddObjectToObject(item, "servedNwdafInfo");
        if (served_nwdaf_info == NULL) {
            ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_nwdaf_info]");
            goto end;
        }
        cJSON *localMapObject = served_nwdaf_info;
        OpenAPI_lnode_t *served_nwdaf_info_node;
        if (nrf_info->served_nwdaf_info) {
            OpenAPI_list_for_each(nrf_info->served_nwdaf_info, served_nwdaf_info_node) {
                OpenAPI_map_t *localKeyValue = (OpenAPI_map_t*)served_nwdaf_info_node->data;
                cJSON *itemLocal = OpenAPI_nwdaf_info_convertToJSON(localKeyValue->value);
                if (itemLocal == NULL) {
                    ogs_error("OpenAPI_nrf_info_convertToJSON() failed [served_nwdaf_info]");
                    goto end;
                }
                cJSON_AddItemToObject(served_nwdaf_info, localKeyValue->key, itemLocal);
            }
        }
    }

end:
    return item;
}

OpenAPI_nrf_info_t *OpenAPI_nrf_info_parseFromJSON(cJSON *nrf_infoJSON)
{
    OpenAPI_nrf_info_t *nrf_info_local_var = NULL;
    cJSON *served_udr_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedUdrInfo");

    OpenAPI_list_t *served_udr_infoList;
    if (served_udr_info) {
        cJSON *served_udr_info_local_map;
        if (!cJSON_IsObject(served_udr_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_udr_info]");
            goto end;
        }
        served_udr_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_udr_info_local_map, served_udr_info) {
            cJSON *localMapObject = served_udr_info_local_map;
            if (!cJSON_IsObject(served_udr_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_udr_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_udr_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_udr_infoList, localMapKeyPair);
        }
    }

    cJSON *served_udm_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedUdmInfo");

    OpenAPI_list_t *served_udm_infoList;
    if (served_udm_info) {
        cJSON *served_udm_info_local_map;
        if (!cJSON_IsObject(served_udm_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_udm_info]");
            goto end;
        }
        served_udm_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_udm_info_local_map, served_udm_info) {
            cJSON *localMapObject = served_udm_info_local_map;
            if (!cJSON_IsObject(served_udm_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_udm_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_udm_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_udm_infoList, localMapKeyPair);
        }
    }

    cJSON *served_ausf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedAusfInfo");

    OpenAPI_list_t *served_ausf_infoList;
    if (served_ausf_info) {
        cJSON *served_ausf_info_local_map;
        if (!cJSON_IsObject(served_ausf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_ausf_info]");
            goto end;
        }
        served_ausf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_ausf_info_local_map, served_ausf_info) {
            cJSON *localMapObject = served_ausf_info_local_map;
            if (!cJSON_IsObject(served_ausf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_ausf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_ausf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_ausf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_amf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedAmfInfo");

    OpenAPI_list_t *served_amf_infoList;
    if (served_amf_info) {
        cJSON *served_amf_info_local_map;
        if (!cJSON_IsObject(served_amf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_amf_info]");
            goto end;
        }
        served_amf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_amf_info_local_map, served_amf_info) {
            cJSON *localMapObject = served_amf_info_local_map;
            if (!cJSON_IsObject(served_amf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_amf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_amf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_amf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_smf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedSmfInfo");

    OpenAPI_list_t *served_smf_infoList;
    if (served_smf_info) {
        cJSON *served_smf_info_local_map;
        if (!cJSON_IsObject(served_smf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_smf_info]");
            goto end;
        }
        served_smf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_smf_info_local_map, served_smf_info) {
            cJSON *localMapObject = served_smf_info_local_map;
            if (!cJSON_IsObject(served_smf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_smf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_smf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_smf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_upf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedUpfInfo");

    OpenAPI_list_t *served_upf_infoList;
    if (served_upf_info) {
        cJSON *served_upf_info_local_map;
        if (!cJSON_IsObject(served_upf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_upf_info]");
            goto end;
        }
        served_upf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_upf_info_local_map, served_upf_info) {
            cJSON *localMapObject = served_upf_info_local_map;
            if (!cJSON_IsObject(served_upf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_upf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_upf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_upf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_pcf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedPcfInfo");

    OpenAPI_list_t *served_pcf_infoList;
    if (served_pcf_info) {
        cJSON *served_pcf_info_local_map;
        if (!cJSON_IsObject(served_pcf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_pcf_info]");
            goto end;
        }
        served_pcf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_pcf_info_local_map, served_pcf_info) {
            cJSON *localMapObject = served_pcf_info_local_map;
            if (!cJSON_IsObject(served_pcf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_pcf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_pcf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_pcf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_bsf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedBsfInfo");

    OpenAPI_list_t *served_bsf_infoList;
    if (served_bsf_info) {
        cJSON *served_bsf_info_local_map;
        if (!cJSON_IsObject(served_bsf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_bsf_info]");
            goto end;
        }
        served_bsf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_bsf_info_local_map, served_bsf_info) {
            cJSON *localMapObject = served_bsf_info_local_map;
            if (!cJSON_IsObject(served_bsf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_bsf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_bsf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_bsf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_chf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedChfInfo");

    OpenAPI_list_t *served_chf_infoList;
    if (served_chf_info) {
        cJSON *served_chf_info_local_map;
        if (!cJSON_IsObject(served_chf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_chf_info]");
            goto end;
        }
        served_chf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_chf_info_local_map, served_chf_info) {
            cJSON *localMapObject = served_chf_info_local_map;
            if (!cJSON_IsObject(served_chf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_chf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_chf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_chf_infoList, localMapKeyPair);
        }
    }

    cJSON *served_nwdaf_info = cJSON_GetObjectItemCaseSensitive(nrf_infoJSON, "servedNwdafInfo");

    OpenAPI_list_t *served_nwdaf_infoList;
    if (served_nwdaf_info) {
        cJSON *served_nwdaf_info_local_map;
        if (!cJSON_IsObject(served_nwdaf_info)) {
            ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_nwdaf_info]");
            goto end;
        }
        served_nwdaf_infoList = OpenAPI_list_create();
        OpenAPI_map_t *localMapKeyPair = NULL;
        cJSON_ArrayForEach(served_nwdaf_info_local_map, served_nwdaf_info) {
            cJSON *localMapObject = served_nwdaf_info_local_map;
            if (!cJSON_IsObject(served_nwdaf_info_local_map)) {
                ogs_error("OpenAPI_nrf_info_parseFromJSON() failed [served_nwdaf_info]");
                goto end;
            }
            localMapKeyPair = OpenAPI_map_create(
                localMapObject->string, OpenAPI_nwdaf_info_parseFromJSON(localMapObject));
            OpenAPI_list_add(served_nwdaf_infoList, localMapKeyPair);
        }
    }

    nrf_info_local_var = OpenAPI_nrf_info_create (
        served_udr_info ? served_udr_infoList : NULL,
        served_udm_info ? served_udm_infoList : NULL,
        served_ausf_info ? served_ausf_infoList : NULL,
        served_amf_info ? served_amf_infoList : NULL,
        served_smf_info ? served_smf_infoList : NULL,
        served_upf_info ? served_upf_infoList : NULL,
        served_pcf_info ? served_pcf_infoList : NULL,
        served_bsf_info ? served_bsf_infoList : NULL,
        served_chf_info ? served_chf_infoList : NULL,
        served_nwdaf_info ? served_nwdaf_infoList : NULL
        );

    return nrf_info_local_var;
end:
    return NULL;
}

