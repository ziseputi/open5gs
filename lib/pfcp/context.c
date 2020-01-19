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
#include "ogs-pfcp.h"

static ogs_pfcp_context_t self;

static OGS_POOL(ogs_pfcp_sess_pool, ogs_pfcp_sess_t);
static OGS_POOL(ogs_pfcp_pdr_pool, ogs_pfcp_pdr_t);
static OGS_POOL(ogs_pfcp_far_pool, ogs_pfcp_far_t);
static OGS_POOL(ogs_pfcp_urr_pool, ogs_pfcp_urr_t);
static OGS_POOL(ogs_pfcp_qer_pool, ogs_pfcp_qer_t);
static OGS_POOL(ogs_pfcp_bar_pool, ogs_pfcp_bar_t);

static int context_initiaized = 0;

void ogs_pfcp_context_init(void)
{
    struct timeval tv;
    ogs_assert(context_initiaized == 0);

    /* Initialize SMF context */
    memset(&self, 0, sizeof(ogs_pfcp_context_t));

    /*
     * PFCP entity uses NTP timestamp(1900), but Open5GS uses UNIX(1970).
     *
     * One is the offset between the two epochs. 
     * Unix uses an epoch located at 1/1/1970-00:00h (UTC) and
     * NTP uses 1/1/1900-00:00h. This leads to an offset equivalent 
     * to 70 years in seconds (there are 17 leap years
     * between the two dates so the offset is
     *
     *  (70*365 + 17)*86400 = 2208988800
     *
     * to be substracted from NTP time to get Unix struct timeval.
     */
    ogs_gettimeofday(&tv);
    self.pfcp_started = tv.tv_sec + 2208988800;

    ogs_log_install_domain(&__ogs_pfcp_domain, "pfcp", ogs_core()->log.level);

    ogs_pfcp_node_init(512);

    ogs_list_init(&self.n4_list);

    ogs_pool_init(&ogs_pfcp_sess_pool, ogs_config()->pool.sess);

    ogs_pool_init(&ogs_pfcp_pdr_pool,
            ogs_config()->pool.sess * OGS_MAX_NUM_OF_PDR);
    ogs_pool_init(&ogs_pfcp_far_pool,
            ogs_config()->pool.sess * OGS_MAX_NUM_OF_FAR);
    ogs_pool_init(&ogs_pfcp_urr_pool,
            ogs_config()->pool.sess * OGS_MAX_NUM_OF_URR);
    ogs_pool_init(&ogs_pfcp_qer_pool,
            ogs_config()->pool.sess * OGS_MAX_NUM_OF_QER);
    ogs_pool_init(&ogs_pfcp_bar_pool,
            ogs_config()->pool.sess * OGS_MAX_NUM_OF_BAR);

    ogs_list_init(&self.sess_list);

    context_initiaized = 1;
}

void ogs_pfcp_context_final(void)
{
    ogs_assert(context_initiaized == 1);

    ogs_pool_final(&ogs_pfcp_sess_pool);
    ogs_pool_final(&ogs_pfcp_pdr_pool);
    ogs_pool_final(&ogs_pfcp_far_pool);
    ogs_pool_final(&ogs_pfcp_urr_pool);
    ogs_pool_final(&ogs_pfcp_qer_pool);
    ogs_pool_final(&ogs_pfcp_bar_pool);

    ogs_pfcp_node_remove_all(&ogs_pfcp_self()->n4_list);

    ogs_pfcp_node_final();

    context_initiaized = 0;
}

ogs_pfcp_context_t *ogs_pfcp_self(void)
{
    return &self;
}

static int ogs_pfcp_context_prepare(void)
{
    self.pfcp_port = OGS_PFCP_UDP_PORT;

    return OGS_OK;
}

static int ogs_pfcp_context_validation(void)
{
    if (ogs_list_first(&self.pfcp_list) == NULL &&
        ogs_list_first(&self.pfcp_list6) == NULL) {
        ogs_error("No smf.pfcp in '%s'",
                ogs_config()->file);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int ogs_pfcp_context_parse_config(const char *local, const char *remote)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_config()->document;
    ogs_assert(document);

    rv = ogs_pfcp_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, local)) {
            ogs_yaml_iter_t ogs_pfcp_iter;
            ogs_yaml_iter_recurse(&root_iter, &ogs_pfcp_iter);
            while (ogs_yaml_iter_next(&ogs_pfcp_iter)) {
                const char *ogs_pfcp_key = ogs_yaml_iter_key(&ogs_pfcp_iter);
                ogs_assert(ogs_pfcp_key);
                if (!strcmp(ogs_pfcp_key, "pfcp")) {
                    ogs_yaml_iter_t pfcp_array, pfcp_iter;
                    ogs_yaml_iter_recurse(&ogs_pfcp_iter, &pfcp_array);
                    do {
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.pfcp_port;
                        const char *dev = NULL;
                        ogs_sockaddr_t *addr = NULL;

                        if (ogs_yaml_iter_type(&pfcp_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&pfcp_iter, &pfcp_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&pfcp_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&pfcp_array))
                                break;
                            ogs_yaml_iter_recurse(&pfcp_array, &pfcp_iter);
                        } else if (ogs_yaml_iter_type(&pfcp_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&pfcp_iter)) {
                            const char *pfcp_key =
                                ogs_yaml_iter_key(&pfcp_iter);
                            ogs_assert(pfcp_key);
                            if (!strcmp(pfcp_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&pfcp_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(pfcp_key, "addr") ||
                                    !strcmp(pfcp_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&pfcp_iter, &hostname_iter);
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
                            } else if (!strcmp(pfcp_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&pfcp_iter);
                                if (v) {
                                    port = atoi(v);
                                    self.pfcp_port = port;
                                }
                            } else if (!strcmp(pfcp_key, "dev")) {
                                dev = ogs_yaml_iter_value(&pfcp_iter);
                            } else if (!strcmp(pfcp_key, "apn")) {
                                /* Skip */
                            } else
                                ogs_warn("unknown key `%s`", pfcp_key);
                        }

                        addr = NULL;
                        for (i = 0; i < num; i++) {
                            rv = ogs_addaddrinfo(&addr,
                                    family, hostname[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        if (addr) {
                            if (ogs_config()->parameter.no_ipv4 == 0) {
                                ogs_sockaddr_t *dup = NULL;
                                rv = ogs_copyaddrinfo(&dup, addr);
                                ogs_assert(rv == OGS_OK);
                                ogs_socknode_add(
                                        &self.pfcp_list, AF_INET, dup);
                            }

                            if (ogs_config()->parameter.no_ipv6 == 0) {
                                ogs_sockaddr_t *dup = NULL;
                                rv = ogs_copyaddrinfo(&dup, addr);
                                ogs_assert(rv == OGS_OK);
                                ogs_socknode_add(
                                        &self.pfcp_list6, AF_INET6, dup);
                            }

                            ogs_freeaddrinfo(addr);
                        }

                        if (dev) {
                            rv = ogs_socknode_probe(
                                    ogs_config()->parameter.no_ipv4 ?
                                        NULL : &self.pfcp_list,
                                    ogs_config()->parameter.no_ipv6 ?
                                        NULL : &self.pfcp_list6,
                                    dev, self.pfcp_port);
                            ogs_assert(rv == OGS_OK);
                        }

                    } while (ogs_yaml_iter_type(&pfcp_array) ==
                            YAML_SEQUENCE_NODE);

                    if (ogs_list_first(&self.pfcp_list) == NULL &&
                        ogs_list_first(&self.pfcp_list6) == NULL) {
                        rv = ogs_socknode_probe(
                                ogs_config()->parameter.no_ipv4 ?
                                    NULL : &self.pfcp_list,
                                ogs_config()->parameter.no_ipv6 ?
                                    NULL : &self.pfcp_list6,
                                NULL, self.pfcp_port);
                        ogs_assert(rv == OGS_OK);
                    }
                }
            }
        } else if (!strcmp(root_key, remote)) {
            ogs_yaml_iter_t upf_iter;
            ogs_yaml_iter_recurse(&root_iter, &upf_iter);
            while (ogs_yaml_iter_next(&upf_iter)) {
                const char *ogs_pfcp_key = ogs_yaml_iter_key(&upf_iter);
                ogs_assert(ogs_pfcp_key);
                if (!strcmp(ogs_pfcp_key, "pfcp")) {
                    ogs_yaml_iter_t pfcp_array, pfcp_iter;
                    ogs_yaml_iter_recurse(&upf_iter, &pfcp_array);
                    do {
                        ogs_pfcp_node_t *pnode = NULL;
                        ogs_sockaddr_t *addr = NULL;
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.pfcp_port;
                        uint16_t tac[OGS_MAX_NUM_OF_TAI] = {0,};
                        uint8_t num_of_tac = 0;

                        if (ogs_yaml_iter_type(&pfcp_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&pfcp_iter, &pfcp_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&pfcp_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&pfcp_array))
                                break;
                            ogs_yaml_iter_recurse(&pfcp_array, &pfcp_iter);
                        } else if (ogs_yaml_iter_type(&pfcp_array) ==
                                YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&pfcp_iter)) {
                            const char *pfcp_key =
                                ogs_yaml_iter_key(&pfcp_iter);
                            ogs_assert(pfcp_key);
                            if (!strcmp(pfcp_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&pfcp_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(pfcp_key, "addr") ||
                                    !strcmp(pfcp_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&pfcp_iter,
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
                            } else if (!strcmp(pfcp_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&pfcp_iter);
                                if (v) port = atoi(v);
                            } else if (!strcmp(pfcp_key, "tac")) {
                                ogs_yaml_iter_t tac_iter;
                                ogs_yaml_iter_recurse(&pfcp_iter, &tac_iter);
                                ogs_assert(ogs_yaml_iter_type(&tac_iter) !=
                                    YAML_MAPPING_NODE);

                                do {
                                    const char *v = NULL;

                                    ogs_assert(num_of_tac <=
                                            OGS_MAX_NUM_OF_TAI);
                                    if (ogs_yaml_iter_type(&tac_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&tac_iter))
                                            break;
                                    }

                                    v = ogs_yaml_iter_value(&tac_iter);
                                    if (v) {
                                        tac[num_of_tac] = atoi(v);
                                        num_of_tac++;
                                    }
                                } while (
                                    ogs_yaml_iter_type(&tac_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else
                                ogs_warn("unknown key `%s`", pfcp_key);
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

                        pnode = ogs_pfcp_node_new(addr);
                        ogs_assert(pnode);
                        ogs_list_add(&self.n4_list, pnode);

                        pnode->num_of_tac = num_of_tac;
                        if (num_of_tac != 0)
                            memcpy(pnode->tac, tac, sizeof(pnode->tac));

                    } while (ogs_yaml_iter_type(&pfcp_array) ==
                            YAML_SEQUENCE_NODE);
                }
            }
        }
    }

    rv = ogs_pfcp_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

int ogs_pfcp_sess_set(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_pdr_t *dl_pdr = NULL;
    ogs_pfcp_pdr_t *ul_pdr = NULL;
    ogs_pfcp_far_t *dl_far = NULL;
    ogs_pfcp_far_t *ul_far = NULL;

    ogs_assert(sess);

    dl_pdr = ogs_pfcp_pdr_add(sess);
    ogs_assert(dl_pdr);
    dl_far = ogs_pfcp_far_add(dl_pdr);
    ogs_assert(dl_far);

    ul_pdr = ogs_pfcp_pdr_add(sess);
    ogs_assert(ul_pdr);
    ul_far = ogs_pfcp_far_add(ul_pdr);
    ogs_assert(ul_far);

    return OGS_OK;
}

void ogs_pfcp_sess_clear(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_pdr_remove_all(sess);
    ogs_pfcp_far_remove_all(sess);
    ogs_pfcp_urr_remove_all(sess);
    ogs_pfcp_qer_remove_all(sess);
    if (sess->bar) ogs_pfcp_bar_delete(sess->bar);
}

ogs_pfcp_pdr_t *ogs_pfcp_pdr_add(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);

    ogs_pool_alloc(&ogs_pfcp_pdr_pool, &pdr);
    ogs_assert(pdr);
    memset(pdr, 0, sizeof *pdr);

    pdr->id = OGS_NEXT_ID(sess->pdr_id, 1, OGS_MAX_NUM_OF_PDR+1);
    pdr->sess = sess;

    ogs_list_add(&sess->pdr_list, pdr);

    return pdr;
}

ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_pdr_id_t id)
{
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->pdr_list, pdr) {
        if (pdr->id == id) return pdr;
    }

    return NULL;
}

ogs_pfcp_pdr_t *ogs_pfcp_pdr_find_or_add(
        ogs_pfcp_sess_t *sess, ogs_pfcp_pdr_id_t id)
{
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);

    pdr = ogs_pfcp_pdr_find_by_id(sess, id);
    if (!pdr)
        pdr = ogs_pfcp_pdr_add(sess);
    ogs_assert(pdr);

    pdr->id = id;

    return pdr;
}

void ogs_pfcp_pdr_remove(ogs_pfcp_pdr_t *pdr)
{
    ogs_assert(pdr);
    ogs_assert(pdr->sess);

    ogs_list_remove(&pdr->sess->pdr_list, pdr);
    ogs_pool_free(&ogs_pfcp_pdr_pool, pdr);
}

void ogs_pfcp_pdr_remove_all(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_pdr_t *pdr = NULL, *next_pdr = NULL;

    ogs_assert(sess);
    ogs_list_for_each_safe(&sess->pdr_list, next_pdr, pdr)
        ogs_pfcp_pdr_remove(pdr);
}

ogs_pfcp_far_t *ogs_pfcp_far_add(ogs_pfcp_pdr_t *pdr)
{
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    ogs_pool_alloc(&ogs_pfcp_far_pool, &far);
    ogs_assert(far);
    memset(far, 0, sizeof *far);

    far->id = OGS_NEXT_ID(sess->far_id, 1, OGS_MAX_NUM_OF_FAR+1);

    far->pdr = pdr;
    pdr->far = far;

    ogs_list_add(&sess->far_list, far);

    return far;
}

ogs_pfcp_far_t *ogs_pfcp_far_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_far_id_t id)
{
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->far_list, far) {
        if (far->id == id) return far;
    }

    return NULL;
}

ogs_pfcp_far_t *ogs_pfcp_far_find_or_add(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_far_id_t id)
{
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    far = ogs_pfcp_far_find_by_id(sess, id);
    if (!far)
        far = ogs_pfcp_far_add(pdr);
    ogs_assert(far);

    far->id = id;

    return far;
}

void ogs_pfcp_far_remove(ogs_pfcp_far_t *far)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(far);
    pdr = far->pdr;
    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    far->pdr = NULL;
    pdr->far = NULL;

    ogs_list_remove(&sess->far_list, far);
    ogs_pool_free(&ogs_pfcp_far_pool, far);
}

void ogs_pfcp_far_remove_all(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_far_t *far = NULL, *next_far = NULL;

    ogs_assert(sess);

    ogs_list_for_each_safe(&sess->far_list, next_far, far)
        ogs_pfcp_far_remove(far);
}

ogs_pfcp_urr_t *ogs_pfcp_urr_add(ogs_pfcp_pdr_t *pdr)
{
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    ogs_pool_alloc(&ogs_pfcp_urr_pool, &urr);
    ogs_assert(urr);
    memset(urr, 0, sizeof *urr);

    urr->id = OGS_NEXT_ID(sess->urr_id, 1, OGS_MAX_NUM_OF_URR+1);

    urr->pdr = pdr;
    pdr->urrs[pdr->num_of_urr++] = urr;

    ogs_list_add(&sess->urr_list, urr);

    return urr;
}

ogs_pfcp_urr_t *ogs_pfcp_urr_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_urr_id_t id)
{
    ogs_pfcp_urr_t *urr = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->urr_list, urr) {
        if (urr->id == id) return urr;
    }

    return NULL;
}

ogs_pfcp_urr_t *ogs_pfcp_urr_find_or_add(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_urr_id_t id)
{
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    urr = ogs_pfcp_urr_find_by_id(sess, id);
    if (!urr)
        urr = ogs_pfcp_urr_add(pdr);
    ogs_assert(urr);

    urr->id = id;

    return urr;
}

void ogs_pfcp_urr_remove(ogs_pfcp_urr_t *urr)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(urr);
    pdr = urr->pdr;
    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    urr->pdr = NULL;
    pdr->urrs[--pdr->num_of_urr] = NULL;

    ogs_list_remove(&sess->urr_list, urr);
    ogs_pool_free(&ogs_pfcp_urr_pool, urr);
}

void ogs_pfcp_urr_remove_all(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_urr_t *urr = NULL, *next_urr = NULL;

    ogs_assert(sess);

    ogs_list_for_each_safe(&sess->urr_list, next_urr, urr)
        ogs_pfcp_urr_remove(urr);
}

ogs_pfcp_qer_t *ogs_pfcp_qer_add(ogs_pfcp_pdr_t *pdr)
{
    ogs_pfcp_qer_t *qer = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    ogs_pool_alloc(&ogs_pfcp_qer_pool, &qer);
    ogs_assert(qer);
    memset(qer, 0, sizeof *qer);

    qer->id = OGS_NEXT_ID(sess->qer_id, 1, OGS_MAX_NUM_OF_QER+1);

    qer->pdr = pdr;
    pdr->qers[pdr->num_of_qer++] = qer;

    ogs_list_add(&sess->qer_list, qer);

    return qer;
}

ogs_pfcp_qer_t *ogs_pfcp_qer_find_by_id(
        ogs_pfcp_sess_t *sess, ogs_pfcp_qer_id_t id)
{
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->qer_list, qer) {
        if (qer->id == id) return qer;
    }

    return NULL;
}

ogs_pfcp_qer_t *ogs_pfcp_qer_find_or_add(
        ogs_pfcp_pdr_t *pdr, ogs_pfcp_qer_id_t id)
{
    ogs_pfcp_qer_t *qer = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    qer = ogs_pfcp_qer_find_by_id(sess, id);
    if (!qer)
        qer = ogs_pfcp_qer_add(pdr);
    ogs_assert(qer);

    qer->id = id;

    return qer;
}

void ogs_pfcp_qer_remove(ogs_pfcp_qer_t *qer)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(qer);
    pdr = qer->pdr;
    ogs_assert(pdr);
    sess = pdr->sess;
    ogs_assert(sess);

    qer->pdr = NULL;
    pdr->qers[--pdr->num_of_qer] = NULL;

    ogs_list_remove(&sess->qer_list, qer);
    ogs_pool_free(&ogs_pfcp_qer_pool, qer);
}

void ogs_pfcp_qer_remove_all(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_qer_t *qer = NULL, *next_qer = NULL;

    ogs_assert(sess);

    ogs_list_for_each_safe(&sess->qer_list, next_qer, qer)
        ogs_pfcp_qer_remove(qer);
}

ogs_pfcp_bar_t *ogs_pfcp_bar_new(ogs_pfcp_sess_t *sess)
{
    ogs_pfcp_bar_t *bar = NULL;

    ogs_assert(sess);
    ogs_assert(sess->bar == NULL); /* Only One BAR is supported */

    ogs_pool_alloc(&ogs_pfcp_bar_pool, &bar);
    ogs_assert(bar);
    memset(bar, 0, sizeof *bar);

    bar->id = 1; /* Always BAR_ID is 1 */

    bar->sess = sess;
    sess->bar = bar;

    return bar;
}

void ogs_pfcp_bar_delete(ogs_pfcp_bar_t *bar)
{
    ogs_pfcp_sess_t *sess = NULL;

    ogs_assert(bar);
    sess = bar->sess;
    ogs_assert(sess);

    bar->sess = NULL;
    sess->bar = NULL;

    ogs_pool_free(&ogs_pfcp_bar_pool, bar);
}
