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

#ifndef OGS_NNRF_BUILD_H
#define OGS_NNRF_BUILD_H

#include "ogs-sbi.h"
#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

OpenAPI_nf_profile_t *ogs_sbi_nnrf_build_nf_profile(
        ogs_sbi_nf_instance_t *nf_instance);
void ogs_sbi_nnrf_free_nf_profile(OpenAPI_nf_profile_t *NFProfile);

#ifdef __cplusplus
}
#endif

#endif /* OGS_NNRF_BUILD_H */
