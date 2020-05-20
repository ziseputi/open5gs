/*
 * up_interface_type.h
 *
 *
 */

#ifndef _OpenAPI_up_interface_type_H_
#define _OpenAPI_up_interface_type_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_up_interface_type_s OpenAPI_up_interface_type_t;
typedef struct OpenAPI_up_interface_type_s {
} OpenAPI_up_interface_type_t;

OpenAPI_up_interface_type_t *OpenAPI_up_interface_type_create(
    );
void OpenAPI_up_interface_type_free(OpenAPI_up_interface_type_t *up_interface_type);
OpenAPI_up_interface_type_t *OpenAPI_up_interface_type_parseFromJSON(cJSON *up_interface_typeJSON);
cJSON *OpenAPI_up_interface_type_convertToJSON(OpenAPI_up_interface_type_t *up_interface_type);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_up_interface_type_H_ */

