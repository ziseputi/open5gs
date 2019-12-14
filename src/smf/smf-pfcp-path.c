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

#include "smf-context.h"

#include "smf-event.h"
#include "smf-sm.h"

#include "smf-pfcp-path.h"

static void pfcp_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];

    ssize_t size;
    smf_event_t *e = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    smf_upf_t *upf = NULL;
    ogs_pfcp_header_t *h = NULL;

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recvfrom() failed");
        ogs_pkbuf_free(pkbuf);
        return;
    }

    ogs_pkbuf_trim(pkbuf, size);

    h = (ogs_pfcp_header_t *)pkbuf->data;
    if (h->version > OGS_PFCP_VERSION) {
        ogs_pfcp_header_t rsp;

        ogs_error("Not supported version[%d]", h->version);

        memset(&rsp, 0, sizeof rsp);
        rsp.flags = (OGS_PFCP_VERSION << 5);
        rsp.type = OGS_PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE;
        rsp.length = htobe16(4);
        rsp.sqn_only = h->sqn_only;
        ogs_sendto(fd, &rsp, 8, 0, &from);
        ogs_pkbuf_free(pkbuf);

        return;
    }

    upf = smf_upf_find_by_addr(&from);
    if (!upf) {
        ogs_error("Unknown UPF : %s", OGS_ADDR(&from, buf));
        ogs_pkbuf_free(pkbuf);
        return;
    }
    ogs_assert(upf->pnode);

    e = smf_event_new(SMF_EVT_N4_MESSAGE);
    ogs_assert(e);
    e->pnode = upf->pnode;
    e->pkbuf = pkbuf;

    rv = ogs_queue_push(smf_self()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_pkbuf_free(e->pkbuf);
        smf_event_free(e);
    }
}

int smf_pfcp_open(void)
{
    smf_upf_t *upf = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    /* PFCP Server */
    ogs_list_for_each(&smf_self()->pfcp_list, node) {
        sock = ogs_pfcp_server(node);
        ogs_assert(sock);
        
        node->poll = ogs_pollset_add(smf_self()->pollset,
                OGS_POLLIN, sock->fd, pfcp_recv_cb, sock);
    }
    ogs_list_for_each(&smf_self()->pfcp_list6, node) {
        sock = ogs_pfcp_server(node);
        ogs_assert(sock);

        node->poll = ogs_pollset_add(smf_self()->pollset,
                OGS_POLLIN, sock->fd, pfcp_recv_cb, sock);
    }

    smf_self()->pfcp_sock = ogs_socknode_sock_first(&smf_self()->pfcp_list);
    if (smf_self()->pfcp_sock)
        smf_self()->pfcp_addr = &smf_self()->pfcp_sock->local_addr;

    smf_self()->pfcp_sock6 = ogs_socknode_sock_first(&smf_self()->pfcp_list6);
    if (smf_self()->pfcp_sock6)
        smf_self()->pfcp_addr6 = &smf_self()->pfcp_sock6->local_addr;

    ogs_assert(smf_self()->pfcp_addr || smf_self()->pfcp_addr6);

    /* PFCP Client */
    ogs_list_for_each(&smf_self()->upf_list, upf) {
        smf_event_t e;
        e.upf = upf;
        e.id = 0;

        ogs_fsm_create(&upf->sm, smf_pfcp_state_initial, smf_pfcp_state_final);
        ogs_fsm_init(&upf->sm, &e);
    }

    return OGS_OK;
}

void smf_pfcp_close(void)
{
    smf_upf_t *upf = NULL;

    /* PFCP Client */
    ogs_list_for_each(&smf_self()->upf_list, upf) {
        smf_event_t e;
        e.upf = upf;

        ogs_fsm_fini(&upf->sm, &e);
        ogs_fsm_delete(&upf->sm);
    }

    /* PFCP Server */
    ogs_socknode_remove_all(&smf_self()->pfcp_list);
    ogs_socknode_remove_all(&smf_self()->pfcp_list6);
}
