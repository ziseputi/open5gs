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

#if !defined(OGS_CORE_INSIDE) && !defined(OGS_CORE_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_UUID_H
#define OGS_UUID_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_UUID_FORMATTED_LENGTH 36

typedef struct {
    unsigned char data[16]; /**< the actual UUID */
} ogs_uuid_t;

void ogs_uuid_get(ogs_uuid_t *uuid);
void ogs_uuid_format(char *buffer, const ogs_uuid_t *uuid);
int ogs_uuid_parse(ogs_uuid_t *uuid, const char *uuid_str);

#ifdef __cplusplus
}
#endif

#endif /* OGS_UUID_H */
