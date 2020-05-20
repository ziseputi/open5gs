/*
 * atom.h
 *
 *
 */

#ifndef _OpenAPI_atom_H_
#define _OpenAPI_atom_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_atom_s OpenAPI_atom_t;
typedef struct OpenAPI_atom_s {
    char *attr;
    char *value;
    int negative;
} OpenAPI_atom_t;

OpenAPI_atom_t *OpenAPI_atom_create(
    char *attr,
    char *value,
    int negative
    );
void OpenAPI_atom_free(OpenAPI_atom_t *atom);
OpenAPI_atom_t *OpenAPI_atom_parseFromJSON(cJSON *atomJSON);
cJSON *OpenAPI_atom_convertToJSON(OpenAPI_atom_t *atom);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_atom_H_ */

