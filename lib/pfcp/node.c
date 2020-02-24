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

#include "ogs-pfcp.h"

static OGS_POOL(cp_pool, ogs_pfcp_cp_node_t);
static OGS_POOL(up_pool, ogs_pfcp_up_node_t);

int ogs_pfcp_node_init(int cp_size, int up_size)
{
    ogs_pool_init(&cp_pool, cp_size);
    ogs_pool_init(&up_pool, up_size);

    return OGS_OK;
}
int ogs_pfcp_node_final(void)
{
    ogs_pool_final(&cp_pool);
    ogs_pool_final(&up_pool);

    return OGS_OK;
}

ogs_pfcp_cp_node_t *ogs_pfcp_cp_node_new(ogs_sockaddr_t *sa_list)
{
    ogs_pfcp_cp_node_t *node = NULL;

    ogs_assert(sa_list);

    ogs_pool_alloc(&cp_pool, &node);
    ogs_assert(node);
    memset(node, 0, sizeof(ogs_pfcp_cp_node_t));

    node->sa_list = sa_list;

    ogs_list_init(&node->local_list);
    ogs_list_init(&node->remote_list);

    ogs_list_init(&node->up_list);

    return node;
}

void ogs_pfcp_cp_node_free(ogs_pfcp_cp_node_t *node)
{
    ogs_assert(node);

    ogs_pfcp_up_node_remove_all(&node->up_list);

    if (node->sock)
        ogs_sock_destroy(node->sock);

    ogs_pfcp_xact_delete_all(node);

    ogs_freeaddrinfo(node->sa_list);
    ogs_pool_free(&cp_pool, node);
}

ogs_pfcp_cp_node_t *ogs_pfcp_cp_node_add(
        ogs_list_t *list, ogs_sockaddr_t *addr)
{
    ogs_pfcp_cp_node_t *node = NULL;
    ogs_sockaddr_t *new = NULL;

    ogs_assert(list);
    ogs_assert(addr);

    ogs_copyaddrinfo(&new, addr);
    node = ogs_pfcp_cp_node_new(new);

    ogs_assert(node);
    memcpy(&node->addr, new, sizeof node->addr);

    ogs_list_add(list, node);

    return node;
}

ogs_pfcp_cp_node_t *ogs_pfcp_cp_node_find(
        ogs_list_t *list, ogs_sockaddr_t *addr)
{
    ogs_pfcp_cp_node_t *node = NULL;

    ogs_assert(list);
    ogs_assert(addr);

    ogs_list_for_each(list, node) {
        if (ogs_sockaddr_is_equal(&node->addr, addr) == true)
            break;
    }

    return node;
}

void ogs_pfcp_cp_node_remove(ogs_list_t *list, ogs_pfcp_cp_node_t *node)
{
    ogs_assert(list);
    ogs_assert(node);

    ogs_list_remove(list, node);
    ogs_pfcp_cp_node_free(node);
}

void ogs_pfcp_cp_node_remove_all(ogs_list_t *list)
{
    ogs_pfcp_cp_node_t *node = NULL, *next_node = NULL;

    ogs_assert(list);
    
    ogs_list_for_each_safe(list, next_node, node)
        ogs_pfcp_cp_node_remove(list, node);
}

ogs_pfcp_up_node_t *ogs_pfcp_up_node_new(
        ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6)
{
    ogs_pfcp_up_node_t *node = NULL;

    ogs_assert(addr || addr6);

    ogs_pool_alloc(&up_pool, &node);
    ogs_assert(node);
    memset(node, 0, sizeof(ogs_pfcp_up_node_t));

    node->addr = addr;
    node->addr6 = addr6;

    /* Not available if source interface == -1 */
    node->source_interface = -1;

    return node;
}

void ogs_pfcp_up_node_free(ogs_pfcp_up_node_t *node)
{
    ogs_assert(node);

    ogs_freeaddrinfo(node->addr);
    ogs_freeaddrinfo(node->addr6);

    ogs_pool_free(&up_pool, node);
}

ogs_pfcp_up_node_t *ogs_pfcp_up_node_add(
        ogs_list_t *list, ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6)
{
    ogs_pfcp_up_node_t *node = NULL;
    ogs_sockaddr_t *new = NULL;
    ogs_sockaddr_t *new6 = NULL;

    ogs_assert(list);
    ogs_assert(addr || addr6);

    ogs_copyaddrinfo(&new, addr);
    ogs_copyaddrinfo(&new6, addr6);
    node = ogs_pfcp_up_node_new(new, new6);
    ogs_assert(node);

    ogs_list_add(list, node);

    return node;
}

void ogs_pfcp_up_node_remove(
        ogs_list_t *list, ogs_pfcp_up_node_t *node)
{
    ogs_assert(list);
    ogs_assert(node);

    ogs_list_remove(list, node);
    ogs_pfcp_up_node_free(node);
}

void ogs_pfcp_up_node_remove_all(ogs_list_t *list)
{
    ogs_pfcp_up_node_t *node = NULL, *next_node = NULL;

    ogs_assert(list);

    ogs_list_for_each_safe(list, next_node, node)
        ogs_pfcp_up_node_remove(list, node);
}
