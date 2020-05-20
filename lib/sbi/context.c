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

#include "app/ogs-app.h"
#include "ogs-sbi.h"

int __ogs_sbi_domain;

static OGS_POOL(nf_instance_pool, ogs_sbi_nf_instance_t);
static OGS_POOL(nf_service_pool, ogs_sbi_nf_service_t);
static OGS_POOL(subscription_pool, ogs_sbi_subscription_t);

static ogs_sbi_context_t self;

static int context_initialized = 0;

void ogs_sbi_context_init(ogs_pollset_t *pollset, ogs_timer_mgr_t *timer_mgr)
{
    ogs_assert(context_initialized == 0);

    /* Initialize SMF context */
    memset(&self, 0, sizeof(ogs_sbi_context_t));

    ogs_assert(pollset);
    self.pollset = pollset;
    ogs_assert(timer_mgr);
    self.timer_mgr = timer_mgr;

    ogs_log_install_domain(&__ogs_sbi_domain, "sbi", ogs_core()->log.level);

    /* FIXME : number of pool size */
    ogs_sbi_message_init(32, 32);
    ogs_sbi_server_init(32);
    ogs_sbi_client_init(512, 512);

    ogs_list_init(&self.nf_instance_list);
    ogs_pool_init(&nf_instance_pool, ogs_config()->pool.sbi);
    ogs_pool_init(&nf_service_pool, ogs_config()->pool.sbi);

    ogs_list_init(&self.subscription_list);
    ogs_pool_init(&subscription_pool, ogs_config()->pool.sbi);

    ogs_uuid_get(&self.uuid);
    ogs_uuid_format(self.nf_instance_id, &self.uuid);

    context_initialized = 1;
}

void ogs_sbi_context_final(void)
{
    ogs_assert(context_initialized == 1);

    ogs_sbi_subscription_remove_all();
    ogs_pool_final(&subscription_pool);

    ogs_sbi_nf_instance_remove_all();
    ogs_pool_final(&nf_instance_pool);
    ogs_pool_final(&nf_service_pool);

    ogs_sbi_client_final();
    ogs_sbi_server_final();
    ogs_sbi_message_final();

    context_initialized = 0;
}

ogs_sbi_context_t *ogs_sbi_self(void)
{
    return &self;
}

static int ogs_sbi_context_prepare(void)
{
    self.http_port = OGS_SBI_HTTP_PORT;
    self.https_port = OGS_SBI_HTTPS_PORT;

    self.content_encoding = "gzip";

    return OGS_OK;
}

static int ogs_sbi_context_validation(const char *local)
{
    if (ogs_list_first(&self.server_list) == NULL) {
        ogs_error("No %s.sbi: in '%s'", local, ogs_config()->file);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_sbi_context_parse_config(const char *local, const char *remote)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_config()->document;
    ogs_assert(document);

    rv = ogs_sbi_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (local && !strcmp(root_key, local)) {
            ogs_yaml_iter_t local_iter;
            ogs_yaml_iter_recurse(&root_iter, &local_iter);
            while (ogs_yaml_iter_next(&local_iter)) {
                const char *local_key = ogs_yaml_iter_key(&local_iter);
                ogs_assert(local_key);
                if (!strcmp(local_key, "sbi")) {
                    ogs_list_t list, list6;
                    ogs_socknode_t *node = NULL, *node6 = NULL;

                    ogs_yaml_iter_t sbi_array, sbi_iter;
                    ogs_yaml_iter_recurse(&local_iter, &sbi_array);
                    do {
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.http_port;
                        const char *dev = NULL;
                        ogs_sockaddr_t *addr = NULL;
                        const char *key = NULL;
                        const char *pem = NULL;

                        if (ogs_yaml_iter_type(&sbi_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&sbi_iter, &sbi_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&sbi_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&sbi_array))
                                break;
                            ogs_yaml_iter_recurse(&sbi_array, &sbi_iter);
                        } else if (ogs_yaml_iter_type(&sbi_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&sbi_iter)) {
                            const char *sbi_key =
                                ogs_yaml_iter_key(&sbi_iter);
                            ogs_assert(sbi_key);
                            if (!strcmp(sbi_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&sbi_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : "
                                        "AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(sbi_key, "addr") ||
                                    !strcmp(sbi_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&sbi_iter,
                                        &hostname_iter);
                                ogs_assert(ogs_yaml_iter_type(&hostname_iter) !=
                                    YAML_MAPPING_NODE);

                                do {
                                    if (ogs_yaml_iter_type(&hostname_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(
                                                    &hostname_iter))
                                            break;
                                    }

                                    ogs_assert(num <= OGS_MAX_NUM_OF_HOSTNAME);
                                    hostname[num++] = 
                                        ogs_yaml_iter_value(&hostname_iter);
                                } while (
                                    ogs_yaml_iter_type(&hostname_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(sbi_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&sbi_iter);
                                if (v) {
                                    port = atoi(v);
                                    self.http_port = port;
                                }
                            } else if (!strcmp(sbi_key, "dev")) {
                                dev = ogs_yaml_iter_value(&sbi_iter);
                            } else if (!strcmp(sbi_key, "tls")) {
                                ogs_yaml_iter_t tls_iter;
                                ogs_yaml_iter_recurse(&sbi_iter, &tls_iter);

                                while (ogs_yaml_iter_next(&tls_iter)) {
                                    const char *tls_key =
                                        ogs_yaml_iter_key(&tls_iter);
                                    ogs_assert(tls_key);

                                    if (!strcmp(tls_key, "key")) {
                                        key = ogs_yaml_iter_value(&tls_iter);
                                    } else if (!strcmp(tls_key, "pem")) {
                                        pem = ogs_yaml_iter_value(&tls_iter);
                                    } else
                                        ogs_warn("unknown key `%s`", tls_key);
                                }
                            } else
                                ogs_warn("unknown key `%s`", sbi_key);
                        }

                        addr = NULL;
                        for (i = 0; i < num; i++) {
                            rv = ogs_addaddrinfo(&addr,
                                    family, hostname[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        ogs_list_init(&list);
                        ogs_list_init(&list6);

                        if (addr) {
                            if (ogs_config()->parameter.no_ipv4 == 0)
                                ogs_socknode_add(&list, AF_INET, addr);
                            if (ogs_config()->parameter.no_ipv6 == 0)
                                ogs_socknode_add(&list6, AF_INET6, addr);
                            ogs_freeaddrinfo(addr);
                        }

                        if (dev) {
                            rv = ogs_socknode_probe(
                                ogs_config()->parameter.no_ipv4 ? NULL : &list,
                                ogs_config()->parameter.no_ipv6 ? NULL : &list6,
                                dev, port);
                            ogs_assert(rv == OGS_OK);
                        }

                        node = ogs_list_first(&list);
                        if (node) {
                            ogs_sbi_server_t *server =
                                ogs_sbi_server_add(node->addr);
                            ogs_assert(server);

                            if (key) server->tls.key = key;
                            if (pem) server->tls.pem = pem;
                        }
                        node6 = ogs_list_first(&list6);
                        if (node6) {
                            ogs_sbi_server_t *server =
                                ogs_sbi_server_add(node6->addr);
                            ogs_assert(server);

                            if (key) server->tls.key = key;
                            if (pem) server->tls.pem = pem;
                        }

                        ogs_socknode_remove_all(&list);
                        ogs_socknode_remove_all(&list6);
                    } while (ogs_yaml_iter_type(&sbi_array) ==
                            YAML_SEQUENCE_NODE);

                    if (ogs_list_first(&self.server_list) == 0) {
                        ogs_list_init(&list);
                        ogs_list_init(&list6);

                        rv = ogs_socknode_probe(
                            ogs_config()->parameter.no_ipv4 ? NULL : &list,
                            ogs_config()->parameter.no_ipv6 ? NULL : &list6,
                            NULL, self.http_port);
                        ogs_assert(rv == OGS_OK);

                        node = ogs_list_first(&list);
                        if (node) ogs_sbi_server_add(node->addr);
                        node6 = ogs_list_first(&list6);
                        if (node6) ogs_sbi_server_add(node6->addr);

                        ogs_socknode_remove_all(&list);
                        ogs_socknode_remove_all(&list6);
                    }
                }
            }
        } else if (remote && !strcmp(root_key, remote)) {
            ogs_yaml_iter_t remote_iter;
            ogs_yaml_iter_recurse(&root_iter, &remote_iter);
            while (ogs_yaml_iter_next(&remote_iter)) {
                const char *remote_key = ogs_yaml_iter_key(&remote_iter);
                ogs_assert(remote_key);
                if (!strcmp(remote_key, "sbi")) {
                    ogs_yaml_iter_t sbi_array, sbi_iter;
                    ogs_yaml_iter_recurse(&remote_iter, &sbi_array);
                    do {
                        ogs_sbi_client_t *client = NULL;
                        ogs_sockaddr_t *addr = NULL;
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.http_port;
                        const char *key = NULL;
                        const char *pem = NULL;

                        if (ogs_yaml_iter_type(&sbi_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&sbi_iter, &sbi_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&sbi_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&sbi_array))
                                break;
                            ogs_yaml_iter_recurse(&sbi_array, &sbi_iter);
                        } else if (ogs_yaml_iter_type(&sbi_array) ==
                                YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&sbi_iter)) {
                            const char *sbi_key =
                                ogs_yaml_iter_key(&sbi_iter);
                            ogs_assert(sbi_key);
                            if (!strcmp(sbi_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&sbi_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : "
                                        "AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(sbi_key, "addr") ||
                                    !strcmp(sbi_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&sbi_iter,
                                        &hostname_iter);
                                ogs_assert(ogs_yaml_iter_type(&hostname_iter) !=
                                    YAML_MAPPING_NODE);

                                do {
                                    if (ogs_yaml_iter_type(&hostname_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&hostname_iter))
                                            break;
                                    }

                                    ogs_assert(num <= OGS_MAX_NUM_OF_HOSTNAME);
                                    hostname[num++] = 
                                        ogs_yaml_iter_value(&hostname_iter);
                                } while (
                                    ogs_yaml_iter_type(&hostname_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(sbi_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&sbi_iter);
                                if (v) port = atoi(v);
                            } else if (!strcmp(sbi_key, "tls")) {
                                ogs_yaml_iter_t tls_iter;
                                ogs_yaml_iter_recurse(&sbi_iter, &tls_iter);

                                while (ogs_yaml_iter_next(&tls_iter)) {
                                    const char *tls_key =
                                        ogs_yaml_iter_key(&tls_iter);
                                    ogs_assert(tls_key);

                                    if (!strcmp(tls_key, "key")) {
                                        key = ogs_yaml_iter_value(&tls_iter);
                                    } else if (!strcmp(tls_key, "pem")) {
                                        pem = ogs_yaml_iter_value(&tls_iter);
                                    } else
                                        ogs_warn("unknown key `%s`", tls_key);
                                }
                            } else
                                ogs_warn("unknown key `%s`", sbi_key);
                        }

                        addr = NULL;
                        for (i = 0; i < num; i++) {
                            rv = ogs_addaddrinfo(&addr,
                                    family, hostname[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        ogs_filter_ip_version(&addr,
                                ogs_config()->parameter.no_ipv4,
                                ogs_config()->parameter.no_ipv6,
                                ogs_config()->parameter.prefer_ipv4);
                        client = ogs_sbi_client_add(addr);
                        ogs_assert(client);

                        if (key) client->tls.key = key;
                        if (pem) client->tls.pem = pem;

                        ogs_freeaddrinfo(addr);

                    } while (ogs_yaml_iter_type(&sbi_array) ==
                            YAML_SEQUENCE_NODE);
                }
            }
        }
    }

    rv = ogs_sbi_context_validation(local);
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

ogs_sbi_nf_instance_t *ogs_sbi_nf_instance_add(char *id)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_assert(id);

    ogs_pool_alloc(&nf_instance_pool, &nf_instance);
    ogs_assert(nf_instance);
    memset(nf_instance, 0, sizeof(ogs_sbi_nf_instance_t));

    nf_instance->id = ogs_strdup(id);
    ogs_assert(nf_instance->id);

    nf_instance->time.heartbeat = ogs_config()->time.nf_instance.heartbeat;

    ogs_list_add(&ogs_sbi_self()->nf_instance_list, nf_instance);

    return nf_instance;
}

void ogs_sbi_nf_instance_clear(ogs_sbi_nf_instance_t *nf_instance)
{
    int i;

    ogs_assert(nf_instance);

    for (i = 0; i < nf_instance->num_of_ipv4; i++) {
        if (nf_instance->ipv4[i])
            ogs_freeaddrinfo(nf_instance->ipv4[i]);
    }
    for (i = 0; i < nf_instance->num_of_ipv6; i++) {
        if (nf_instance->ipv6[i])
            ogs_freeaddrinfo(nf_instance->ipv6[i]);
    }


    ogs_sbi_nf_service_remove_all(nf_instance);
}

void ogs_sbi_nf_instance_remove(ogs_sbi_nf_instance_t *nf_instance)
{
    ogs_assert(nf_instance);

    ogs_list_remove(&ogs_sbi_self()->nf_instance_list, nf_instance);

    ogs_sbi_subscription_remove_all_by_nf_instance_id(nf_instance->id);

    ogs_assert(nf_instance->id);
    ogs_free(nf_instance->id);

    ogs_sbi_nf_instance_clear(nf_instance);

    ogs_pool_free(&nf_instance_pool, nf_instance);
}

void ogs_sbi_nf_instance_remove_all(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL, *next_nf_instance = NULL;

    ogs_list_for_each_safe(
            &ogs_sbi_self()->nf_instance_list, next_nf_instance, nf_instance)
        ogs_sbi_nf_instance_remove(nf_instance);
}

ogs_sbi_nf_instance_t *ogs_sbi_nf_instance_find(char *id)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_assert(id);

    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
        ogs_assert(nf_instance->id);
        if (strcmp(nf_instance->id, id) == 0)
            break;
    }

    return nf_instance;
}

ogs_sbi_nf_instance_t *ogs_sbi_nf_instance_build_default(
        OpenAPI_nf_type_e nf_type, ogs_sbi_client_t *client)
{
    ogs_sbi_server_t *server = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    char *hostname = NULL;

    nf_instance = ogs_sbi_nf_instance_add(ogs_sbi_self()->nf_instance_id);
    ogs_assert(nf_instance);

    nf_instance->nf_type = nf_type;
    nf_instance->nf_status = OpenAPI_nf_status_REGISTERED;
    OGS_SETUP_SBI_CLIENT(nf_instance, client);

    hostname = NULL;
    ogs_list_for_each(&ogs_sbi_self()->server_list, server) {
        ogs_assert(server->addr);

        /* First FQDN is selected */
        if (!hostname) {
            hostname = ogs_gethostname(server->addr);
            if (hostname)
                continue;
        }

        if (nf_instance->num_of_ipv4 < OGS_SBI_MAX_NUM_OF_IP_ADDRESS) {
            ogs_sockaddr_t *addr = NULL;
            ogs_copyaddrinfo(&addr, server->addr);
            ogs_assert(addr);

            if (addr->ogs_sa_family == AF_INET) {
                nf_instance->ipv4[nf_instance->num_of_ipv4] = addr;
                nf_instance->num_of_ipv4++;
            } else if (addr->ogs_sa_family == AF_INET6) {
                nf_instance->ipv6[nf_instance->num_of_ipv6] = addr;
                nf_instance->num_of_ipv6++;
            } else
                ogs_assert_if_reached();
        }
    }

    if (hostname)
        strcpy(nf_instance->fqdn, hostname);

    return nf_instance;
}

ogs_sbi_nf_service_t *ogs_sbi_nf_service_add(ogs_sbi_nf_instance_t *nf_instance,
        char *id, char *name, OpenAPI_uri_scheme_e scheme)
{
    ogs_sbi_nf_service_t *nf_service = NULL;

    ogs_assert(nf_instance);
    ogs_assert(id);
    ogs_assert(name);

    ogs_pool_alloc(&nf_service_pool, &nf_service);
    ogs_assert(nf_service);
    memset(nf_service, 0, sizeof(ogs_sbi_nf_service_t));

    nf_service->id = ogs_strdup(id);
    ogs_assert(nf_service->id);
    nf_service->name = ogs_strdup(name);
    ogs_assert(nf_service->name);
    nf_service->scheme = scheme;

    nf_service->status = OpenAPI_nf_service_status_REGISTERED;

    nf_service->nf_instance = nf_instance;

    ogs_list_add(&nf_instance->nf_service_list, nf_service);

    return nf_service;
}

void ogs_sbi_nf_service_add_version(ogs_sbi_nf_service_t *nf_service,
        char *in_uri, char *full, char *expiry)
{
    ogs_assert(nf_service);

    ogs_assert(in_uri);
    ogs_assert(full);

    if (nf_service->num_of_version < OGS_SBI_MAX_NUM_OF_SERVICE_VERSION) {
        nf_service->versions[nf_service->num_of_version].in_uri =
            ogs_strdup(in_uri);
        nf_service->versions[nf_service->num_of_version].full =
            ogs_strdup(full);
        if (expiry)
            nf_service->versions[nf_service->num_of_version].expiry =
                ogs_strdup(expiry);
        nf_service->num_of_version++;
    }
}

void ogs_sbi_nf_service_remove(ogs_sbi_nf_instance_t *nf_instance,
        ogs_sbi_nf_service_t *nf_service)
{
    int i;

    ogs_assert(nf_instance);
    ogs_assert(nf_service);

    ogs_list_remove(&nf_instance->nf_service_list, nf_service);

    ogs_assert(nf_service->id);
    ogs_free(nf_service->id);

    ogs_assert(nf_service->name);
    ogs_free(nf_service->name);

    for (i = 0; i < nf_service->num_of_version; i++) {
        if (nf_service->versions[i].in_uri)
            ogs_free(nf_service->versions[i].in_uri);
        if (nf_service->versions[i].full)
            ogs_free(nf_service->versions[i].full);
        if (nf_service->versions[i].expiry)
            ogs_free(nf_service->versions[i].expiry);
    }

    for (i = 0; i < nf_service->num_of_addr; i++) {
        if (nf_service->addr[i].ipv4)
            ogs_freeaddrinfo(nf_service->addr[i].ipv4);
        if (nf_service->addr[i].ipv6)
            ogs_freeaddrinfo(nf_service->addr[i].ipv6);
    }

    ogs_pool_free(&nf_service_pool, nf_service);
}

void ogs_sbi_nf_service_remove_all(ogs_sbi_nf_instance_t *nf_instance)
{
    ogs_sbi_nf_service_t *nf_service = NULL, *next_nf_service = NULL;

    ogs_assert(nf_instance);

    ogs_list_for_each_safe(&nf_instance->nf_service_list,
            next_nf_service, nf_service)
        ogs_sbi_nf_service_remove(nf_instance, nf_service);
}

ogs_sbi_nf_service_t *ogs_sbi_nf_service_find(
        ogs_sbi_nf_instance_t *nf_instance, char *name)
{
    ogs_sbi_nf_service_t *nf_service = NULL;

    ogs_assert(nf_instance);
    ogs_assert(name);

    ogs_list_for_each(&nf_instance->nf_service_list, nf_service) {
        ogs_assert(nf_service->name);
        if (strcmp(nf_service->name, name) == 0)
            break;
    }

    return nf_service;
}

ogs_sbi_nf_service_t *ogs_sbi_nf_service_build_default(
        ogs_sbi_nf_instance_t *nf_instance,
        char *name, ogs_sbi_client_t *client)
{
    ogs_sbi_server_t *server = NULL;
    ogs_sbi_nf_service_t *nf_service = NULL;
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    char *hostname = NULL;

    ogs_assert(nf_instance);
    ogs_assert(name);
    ogs_assert(client);

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    nf_service = ogs_sbi_nf_service_add(nf_instance, id, name,
        (client->tls.key && client->tls.pem) ?
            OpenAPI_uri_scheme_https : OpenAPI_uri_scheme_http);
    ogs_assert(nf_service);
    OGS_SETUP_SBI_CLIENT(nf_service, client);

    hostname = NULL;
    ogs_list_for_each(&ogs_sbi_self()->server_list, server) {
        ogs_assert(server->addr);

        /* First FQDN is selected */
        if (!hostname) {
            hostname = ogs_gethostname(server->addr);
            if (hostname)
                continue;
        }

        if (nf_service->num_of_addr < OGS_SBI_MAX_NUM_OF_IP_ADDRESS) {
            int port = 0;
            ogs_sockaddr_t *addr = NULL;
            ogs_copyaddrinfo(&addr, server->addr);
            ogs_assert(addr);

            port = OGS_PORT(addr);
            if (nf_service->scheme == OpenAPI_uri_scheme_https) {
                if (port == OGS_SBI_HTTPS_PORT) port = 0;
            } else if (nf_service->scheme == OpenAPI_uri_scheme_http) {
                if (port == OGS_SBI_HTTP_PORT) port = 0;
            }

            nf_service->addr[nf_service->num_of_addr].port = port;
            if (addr->ogs_sa_family == AF_INET) {
                nf_service->addr[nf_service->num_of_addr].ipv4 = addr;
            } else if (addr->ogs_sa_family == AF_INET6) {
                nf_service->addr[nf_service->num_of_addr].ipv6 = addr;
            } else
                ogs_assert_if_reached();

            nf_service->num_of_addr++;
        }
    }

    if (hostname)
        strcpy(nf_service->fqdn, hostname);

    return nf_service;
}

static ogs_sbi_client_t *find_client_by_fqdn(char *fqdn, int port)
{
    int rv;
    ogs_sockaddr_t *addr = NULL;
    ogs_sbi_client_t *client = NULL;

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC, fqdn,
            port ? port : OGS_SBI_HTTPS_PORT, 0);
    if (rv != OGS_OK) {
        ogs_error("Invalid NFProfile.fqdn");
        return NULL;
    }

    client = ogs_sbi_client_find(addr);
    if (!client) {
        client = ogs_sbi_client_add(addr);
        ogs_assert(client);
    }

    ogs_freeaddrinfo(addr);

    return client;
}

ogs_sbi_client_t *ogs_sbi_nf_instance_find_client(
        ogs_sbi_nf_instance_t *nf_instance)
{
    ogs_sbi_client_t *client = NULL;
    ogs_sockaddr_t *addr = NULL;

    if (strlen(nf_instance->fqdn))
        client = find_client_by_fqdn(nf_instance->fqdn, 0);

    if (!client) {
        /* At this point, CLIENT selection method is very simple. */
        if (nf_instance->num_of_ipv4) addr = nf_instance->ipv4[0];
        if (nf_instance->num_of_ipv6) addr = nf_instance->ipv6[0];

        if (addr) {
            client = ogs_sbi_client_find(addr);
            if (!client) {
                client = ogs_sbi_client_add(addr);
                ogs_assert(client);
            }
        }
    }

    ogs_sbi_nf_service_find_client_all(nf_instance);

    return client;
}

ogs_sbi_client_t *ogs_sbi_nf_service_find_client(
        ogs_sbi_nf_service_t *nf_service)
{
    ogs_sbi_client_t *client = NULL;
    ogs_sockaddr_t *addr = NULL;

    if (strlen(nf_service->fqdn))
        client = find_client_by_fqdn(nf_service->fqdn, 0);

    if (!client) {
        /* At this point, CLIENT selection method is very simple. */
        if (nf_service->num_of_addr) {
            addr = nf_service->addr[0].ipv6;
            if (!addr)
                addr = nf_service->addr[0].ipv4;
        }

        if (addr) {
            client = ogs_sbi_client_find(addr);
            if (!client) {
                client = ogs_sbi_client_add(addr);
                ogs_assert(client);
            }
        }
    }

    if (!client) {
        ogs_sbi_nf_instance_t *nf_instance = NULL;
        nf_instance = nf_service->nf_instance;
        ogs_assert(nf_instance);
        client = nf_instance->client;
    }

    return client;
}

void ogs_sbi_nf_service_find_client_all(ogs_sbi_nf_instance_t *nf_instance)
{
    ogs_sbi_nf_service_t *nf_service = NULL;

    ogs_assert(nf_instance);

    ogs_list_for_each(&nf_instance->nf_service_list, nf_service)
        ogs_sbi_nf_service_find_client(nf_service);
}

ogs_sbi_subscription_t *ogs_sbi_subscription_add(void)
{
    ogs_sbi_subscription_t *subscription = NULL;

    ogs_pool_alloc(&subscription_pool, &subscription);
    ogs_assert(subscription);
    memset(subscription, 0, sizeof(ogs_sbi_subscription_t));

    subscription->time.validity = ogs_config()->time.subscription.validity;

    ogs_list_add(&ogs_sbi_self()->subscription_list, subscription);

    return subscription;
}

void ogs_sbi_subscription_set_id(ogs_sbi_subscription_t *subscription, char *id)
{
    ogs_assert(subscription);
    ogs_assert(id);

    subscription->id = ogs_strdup(id);
    ogs_assert(subscription->id);
}

void ogs_sbi_subscription_remove(ogs_sbi_subscription_t *subscription)
{
    ogs_assert(subscription);

    ogs_list_remove(&ogs_sbi_self()->subscription_list, subscription);

    if (subscription->id)
        ogs_free(subscription->id);

    if (subscription->notification_uri)
        ogs_free(subscription->notification_uri);

    if (subscription->nf_instance_id)
        ogs_free(subscription->nf_instance_id);

    if (subscription->t_validity)
        ogs_timer_delete(subscription->t_validity);

    ogs_pool_free(&subscription_pool, subscription);
}

void ogs_sbi_subscription_remove_all_by_nf_instance_id(char *nf_instance_id)
{
    ogs_sbi_subscription_t *subscription = NULL, *next_subscription = NULL;

    ogs_assert(nf_instance_id);

    ogs_list_for_each_safe(&ogs_sbi_self()->subscription_list,
            next_subscription, subscription) {
        if (subscription->nf_instance_id &&
            strcmp(subscription->nf_instance_id, nf_instance_id) == 0) {
            ogs_sbi_subscription_remove(subscription);
        }
    }
}

void ogs_sbi_subscription_remove_all(void)
{
    ogs_sbi_subscription_t *subscription = NULL, *next_subscription = NULL;

    ogs_list_for_each_safe(&ogs_sbi_self()->subscription_list,
            next_subscription, subscription)
        ogs_sbi_subscription_remove(subscription);
}

ogs_sbi_subscription_t *ogs_sbi_subscription_find(char *id)
{
    ogs_sbi_subscription_t *subscription = NULL;

    ogs_assert(id);

    ogs_list_for_each(&ogs_sbi_self()->subscription_list, subscription) {
        ogs_assert(subscription->id);
        if (strcmp(subscription->id, id) == 0)
            break;
    }

    return subscription;
}
