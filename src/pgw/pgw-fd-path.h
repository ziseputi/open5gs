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

#ifndef PGW_FD_PATH_H
#define PGW_FD_PATH_H

#include "pgw-context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gtp_xact_s gtp_xact_t;

int pgw_fd_init(void);
void pgw_fd_final(void);

void pgw_gx_send_ccr(pgw_sess_t *sess, ogs_gtp_xact_t *xact,
        uint32_t cc_request_type);

#ifdef __cplusplus
}
#endif

#endif /* PGW_FD_PATH_H */

