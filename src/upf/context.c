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

#include "context.h"

static upf_context_t self;
static ogs_diam_config_t g_diam_conf;

int __upf_log_domain;

static OGS_POOL(upf_dev_pool, upf_dev_t);
static OGS_POOL(upf_subnet_pool, upf_subnet_t);

static OGS_POOL(upf_sess_pool, upf_sess_t);
static OGS_POOL(upf_bearer_pool, upf_bearer_t);

static OGS_POOL(upf_pf_pool, upf_pf_t);

static int context_initiaized = 0;

int num_sessions = 0;
void stats_add_session(void) {
    num_sessions = num_sessions + 1;
    ogs_info("Added a session. Number of active sessions is now %d", num_sessions);
}

void stats_remove_session(void) {
    num_sessions = num_sessions - 1;
    ogs_info("Removed a session. Number of active sessions is now %d", num_sessions);
}

void upf_context_init(void)
{
    struct timeval tv;
    ogs_assert(context_initiaized == 0);

    /* Initial FreeDiameter Config */
    memset(&g_diam_conf, 0, sizeof(ogs_diam_config_t));

    /* Initialize UPF context */
    memset(&self, 0, sizeof(upf_context_t));
    self.diam_config = &g_diam_conf;

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

    ogs_log_install_domain(&__ogs_gtp_domain, "gtp", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_pfcp_domain, "pfcp", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_diam_domain, "diam", ogs_core()->log.level);
    ogs_log_install_domain(&__upf_log_domain, "upf", ogs_core()->log.level);

    ogs_gtp_node_init(512);
    ogs_pfcp_node_init(512);

    ogs_list_init(&self.gtpc_list);
    ogs_list_init(&self.gtpc_list6);
    ogs_list_init(&self.gtpu_list);
    ogs_list_init(&self.gtpu_list6);

    ogs_list_init(&self.sgw_s5c_list);
    ogs_list_init(&self.sgw_s5u_list);
    ogs_list_init(&self.smf_n4_list);

    ogs_list_init(&self.dev_list);
    ogs_pool_init(&upf_dev_pool, MAX_NUM_OF_DEV);
    ogs_list_init(&self.subnet_list);
    ogs_pool_init(&upf_subnet_pool, MAX_NUM_OF_SUBNET);

    ogs_pool_init(&upf_sess_pool, ogs_config()->pool.sess);
    ogs_pool_init(&upf_bearer_pool, ogs_config()->pool.bearer);

    ogs_pool_init(&upf_pf_pool, ogs_config()->pool.pf);

    self.sess_hash = ogs_hash_make();

    ogs_list_init(&self.sess_list);

    context_initiaized = 1;
}

void upf_context_final(void)
{
    ogs_assert(context_initiaized == 1);

    upf_sess_remove_all();

    upf_dev_remove_all();
    upf_subnet_remove_all();

    ogs_assert(self.sess_hash);
    ogs_hash_destroy(self.sess_hash);

    ogs_pool_final(&upf_bearer_pool);
    ogs_pool_final(&upf_sess_pool);
    ogs_pool_final(&upf_pf_pool);

    ogs_pool_final(&upf_dev_pool);
    ogs_pool_final(&upf_subnet_pool);

    ogs_gtp_node_remove_all(&self.sgw_s5c_list);
    ogs_gtp_node_remove_all(&self.sgw_s5u_list);

    ogs_pfcp_node_remove_all(&upf_self()->smf_n4_list);

    ogs_gtp_node_final();
    ogs_pfcp_node_final();

    context_initiaized = 0;
}

upf_context_t *upf_self(void)
{
    return &self;
}

static int upf_context_prepare(void)
{
    self.gtpc_port = OGS_GTPV2_C_UDP_PORT;
    self.gtpu_port = OGS_GTPV1_U_UDP_PORT;
    self.pfcp_port = OGS_PFCP_UDP_PORT;
    self.diam_config->cnf_port = DIAMETER_PORT;
    self.diam_config->cnf_port_tls = DIAMETER_SECURE_PORT;

    self.tun_ifname = "ogstun";

    return OGS_OK;
}

static int upf_context_validation(void)
{
    if (ogs_list_first(&self.pfcp_list) == NULL &&
        ogs_list_first(&self.pfcp_list6) == NULL) {
        ogs_error("No upf.pfcp in '%s'",
                ogs_config()->file);
        return OGS_ERROR;
    }
    if (ogs_list_first(&self.gtpu_list) == NULL &&
        ogs_list_first(&self.gtpu_list6) == NULL) {
        ogs_error("No upf.gtpu in '%s'",
                ogs_config()->file);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int upf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_config()->document;
    ogs_assert(document);

    rv = upf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "upf")) {
            ogs_yaml_iter_t upf_iter;
            ogs_yaml_iter_recurse(&root_iter, &upf_iter);
            while (ogs_yaml_iter_next(&upf_iter)) {
                const char *upf_key = ogs_yaml_iter_key(&upf_iter);
                ogs_assert(upf_key);
                if (!strcmp(upf_key, "gtpu")) {
                    ogs_yaml_iter_t gtpu_array, gtpu_iter;
                    ogs_yaml_iter_recurse(&upf_iter, &gtpu_array);
                    do {
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.gtpu_port;
                        const char *dev = NULL;
                        ogs_sockaddr_t *addr = NULL;

                        if (ogs_yaml_iter_type(&gtpu_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&gtpu_iter, &gtpu_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&gtpu_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&gtpu_array))
                                break;
                            ogs_yaml_iter_recurse(&gtpu_array, &gtpu_iter);
                        } else if (ogs_yaml_iter_type(&gtpu_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&gtpu_iter)) {
                            const char *gtpu_key =
                                ogs_yaml_iter_key(&gtpu_iter);
                            ogs_assert(gtpu_key);
                            if (!strcmp(gtpu_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&gtpu_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(gtpu_key, "addr") ||
                                    !strcmp(gtpu_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&gtpu_iter, &hostname_iter);
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
                            } else if (!strcmp(gtpu_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&gtpu_iter);
                                if (v) {
                                    port = atoi(v);
                                    self.gtpu_port = port;
                                }
                            } else if (!strcmp(gtpu_key, "dev")) {
                                dev = ogs_yaml_iter_value(&gtpu_iter);
                            } else
                                ogs_warn("unknown key `%s`", gtpu_key);
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
                                        &self.gtpu_list, AF_INET, dup);
                            }

                            if (ogs_config()->parameter.no_ipv6 == 0) {
                                ogs_sockaddr_t *dup = NULL;
                                rv = ogs_copyaddrinfo(&dup, addr);
                                ogs_assert(rv == OGS_OK);
                                ogs_socknode_add(
                                        &self.gtpu_list6, AF_INET6, dup);
                            }

                            ogs_freeaddrinfo(addr);
                        }

                        if (dev) {
                            rv = ogs_socknode_probe(
                                    ogs_config()->parameter.no_ipv4 ?
                                        NULL : &self.gtpu_list,
                                    ogs_config()->parameter.no_ipv6 ?
                                        NULL : &self.gtpu_list6,
                                    dev, self.gtpu_port);
                            ogs_assert(rv == OGS_OK);
                        }

                    } while (ogs_yaml_iter_type(&gtpu_array) == 
                            YAML_SEQUENCE_NODE);

                    if (ogs_list_first(&self.gtpu_list) == NULL &&
                        ogs_list_first(&self.gtpu_list6) == NULL) {
                        rv = ogs_socknode_probe(
                                ogs_config()->parameter.no_ipv4 ?
                                    NULL : &self.gtpu_list,
                                ogs_config()->parameter.no_ipv6 ?
                                    NULL : &self.gtpu_list6,
                                NULL, self.gtpu_port);
                        ogs_assert(rv == OGS_OK);
                    }
                } else if (!strcmp(upf_key, "pfcp")) {
                    ogs_yaml_iter_t pfcp_array, pfcp_iter;
                    ogs_yaml_iter_recurse(&upf_iter, &pfcp_array);
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
        } else if (!strcmp(root_key, "smf")) {
            ogs_yaml_iter_t upf_iter;
            ogs_yaml_iter_recurse(&root_iter, &upf_iter);
            while (ogs_yaml_iter_next(&upf_iter)) {
                const char *upf_key = ogs_yaml_iter_key(&upf_iter);
                ogs_assert(upf_key);
                if (!strcmp(upf_key, "pfcp")) {
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
                        ogs_list_add(&self.smf_n4_list, pnode);

                        pnode->num_of_tac = num_of_tac;
                        if (num_of_tac != 0)
                            memcpy(pnode->tac, tac, sizeof(pnode->tac));

                    } while (ogs_yaml_iter_type(&pfcp_array) ==
                            YAML_SEQUENCE_NODE);
                }
            }
        }
    }

    rv = upf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

static void *sess_hash_keygen(uint8_t *out, int *out_len,
        uint8_t *imsi, int imsi_len, char *apn)
{
    memcpy(out, imsi, imsi_len);
    ogs_cpystrn((char*)(out+imsi_len), apn, OGS_MAX_APN_LEN+1);
    *out_len = imsi_len+strlen((char*)(out+imsi_len));

    return out;
}

upf_sess_t *upf_sess_add(
        uint8_t *imsi, int imsi_len, char *apn, 
        uint8_t pdn_type, uint8_t ebi, ogs_paa_t *paa)
{
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];
    upf_sess_t *sess = NULL;
    upf_bearer_t *bearer = NULL;
    upf_subnet_t *subnet6 = NULL;

    ogs_assert(imsi);
    ogs_assert(apn);
    ogs_assert(paa);

    ogs_pool_alloc(&upf_sess_pool, &sess);
    ogs_assert(sess);
    memset(sess, 0, sizeof *sess);

    sess->index = ogs_pool_index(&upf_sess_pool, sess);
    ogs_assert(sess->index > 0 && sess->index <= ogs_config()->pool.sess);

    sess->upf_s5c_teid = sess->index;
    sess->smf_n4_seid = sess->index;

    /* Set IMSI */
    sess->imsi_len = imsi_len;
    memcpy(sess->imsi, imsi, sess->imsi_len);
    ogs_buffer_to_bcd(sess->imsi, sess->imsi_len, sess->imsi_bcd);

    /* Set APN */
    ogs_cpystrn(sess->pdn.apn, apn, OGS_MAX_APN_LEN+1);

    ogs_list_init(&sess->bearer_list);

    ogs_cpystrn(sess->pdn.apn, apn, OGS_MAX_APN_LEN+1);

    bearer = upf_bearer_add(sess);
    ogs_assert(bearer);
    bearer->ebi = ebi;

    sess->pdn.paa.pdn_type = pdn_type;
    ogs_assert(pdn_type == paa->pdn_type);

    if (pdn_type == OGS_GTP_PDN_TYPE_IPV4) {
        sess->ipv4 = upf_ue_ip_alloc(AF_INET, apn, (uint8_t *)&(paa->addr));
        ogs_assert(sess->ipv4);
        sess->pdn.paa.addr = sess->ipv4->addr[0];
    } else if (pdn_type == OGS_GTP_PDN_TYPE_IPV6) {
        sess->ipv6 = upf_ue_ip_alloc(AF_INET6, apn, (paa->addr6));
        ogs_assert(sess->ipv6);

        subnet6 = sess->ipv6->subnet;
        ogs_assert(subnet6);

        sess->pdn.paa.len = subnet6->prefixlen;
        memcpy(sess->pdn.paa.addr6, sess->ipv6->addr, OGS_IPV6_LEN);
    } else if (pdn_type == OGS_GTP_PDN_TYPE_IPV4V6) {
        sess->ipv4 = upf_ue_ip_alloc(AF_INET, apn, (uint8_t *)&(paa->both.addr));
        ogs_assert(sess->ipv4);
        sess->ipv6 = upf_ue_ip_alloc(AF_INET6, apn, (paa->both.addr6));
        ogs_assert(sess->ipv6);

        subnet6 = sess->ipv6->subnet;
        ogs_assert(subnet6);

        sess->pdn.paa.both.addr = sess->ipv4->addr[0];
        sess->pdn.paa.both.len = subnet6->prefixlen;
        memcpy(sess->pdn.paa.both.addr6, sess->ipv6->addr, OGS_IPV6_LEN);
    } else
        ogs_assert_if_reached();

    /* Select PFCP Node */
    if (upf_self()->upf == NULL)
        upf_self()->upf = ogs_list_first(&upf_self()->smf_n4_list);

    ogs_assert(upf_self()->upf);
    OGS_SETUP_PFCP_NODE(sess, upf_self()->upf);

    ogs_info("UE IMSI:[%s] APN:[%s] IPv4:[%s] IPv6:[%s]",
	    sess->imsi_bcd,
	    apn,
            sess->ipv4 ?  INET_NTOP(&sess->ipv4->addr, buf1) : "",
            sess->ipv6 ?  INET6_NTOP(&sess->ipv6->addr, buf2) : "");

     /* Generate Hash Key : IMSI + APN */
    sess_hash_keygen(sess->hash_keybuf, &sess->hash_keylen,
            imsi, imsi_len, apn);
    ogs_hash_set(self.sess_hash, sess->hash_keybuf, sess->hash_keylen, sess);

    ogs_list_add(&self.sess_list, sess);
    
    stats_add_session();

    return sess;
}

int upf_sess_remove(upf_sess_t *sess)
{
    ogs_assert(sess);

    ogs_list_remove(&self.sess_list, sess);

    OGS_MEM_CLEAR(sess->create_session_request);
    OGS_MEM_CLEAR(sess->delete_session_request);

    ogs_hash_set(self.sess_hash, sess->hash_keybuf, sess->hash_keylen, NULL);

    if (sess->ipv4)
        upf_ue_ip_free(sess->ipv4);
    if (sess->ipv6)
        upf_ue_ip_free(sess->ipv6);

    upf_bearer_remove_all(sess);

    ogs_pool_free(&upf_sess_pool, sess);

    stats_remove_session();

    return OGS_OK;
}

void upf_sess_remove_all(void)
{
    upf_sess_t *sess = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.sess_list, next, sess)
        upf_sess_remove(sess);
}

upf_sess_t *upf_sess_find(uint32_t index)
{
    ogs_assert(index);
    return ogs_pool_find(&upf_sess_pool, index);
}

upf_sess_t *upf_sess_find_by_teid(uint32_t teid)
{
    return upf_sess_find(teid);
}

upf_sess_t *upf_sess_find_by_seid(uint64_t seid)
{
    return upf_sess_find(seid);
}

upf_sess_t *upf_sess_find_by_imsi_apn(
    uint8_t *imsi, int imsi_len, char *apn)
{
    uint8_t keybuf[OGS_MAX_IMSI_LEN+OGS_MAX_APN_LEN+1];
    int keylen = 0;

    ogs_assert(self.sess_hash);

    sess_hash_keygen(keybuf, &keylen, imsi, imsi_len, apn);
    return (upf_sess_t *)ogs_hash_get(self.sess_hash, keybuf, keylen);
}

upf_sess_t *upf_sess_add_by_message(ogs_gtp_message_t *message)
{
    upf_sess_t *sess = NULL;
    ogs_paa_t *paa = NULL;
    char apn[OGS_MAX_APN_LEN];

    ogs_gtp_create_session_request_t *req = &message->create_session_request;

    if (req->imsi.presence == 0) {
        ogs_error("No IMSI");
        return NULL;
    }
    if (req->access_point_name.presence == 0) {
        ogs_error("No APN");
        return NULL;
    }
    if (req->bearer_contexts_to_be_created.presence == 0) {
        ogs_error("No Bearer");
        return NULL;
    }
    if (req->bearer_contexts_to_be_created.eps_bearer_id.presence == 0) {
        ogs_error("No EPS Bearer ID");
        return NULL;
    }
    if (req->pdn_type.presence == 0) {
        ogs_error("No PDN Type");
        return NULL;
    }

    if (req->pdn_address_allocation.presence == 0) {
        ogs_error("No PAA Type");
        return NULL;
    }

    ogs_fqdn_parse(apn,
            req->access_point_name.data, req->access_point_name.len);

    ogs_trace("upf_sess_add_by_message() [APN:%s, PDN:%d, EDI:%d]",
            apn, req->pdn_type.u8,
            req->bearer_contexts_to_be_created.eps_bearer_id.u8);

    paa = (ogs_paa_t *)req->pdn_address_allocation.data;

    /* 
     * 7.2.1 in 3GPP TS 29.274 Release 15
     *
     * If the new Create Session Request received by the UPF collides with
     * an existing PDN connection context (the existing PDN connection context
     * is identified with the triplet [IMSI, EPS Bearer ID, Interface type],
     * where applicable Interface type here is S2a TWAN GTP-C interface or
     * S2b ePDG GTP-C interface or S5/S8 SGW GTP-C interface, and where IMSI
     * shall be replaced by TAC and SNR part of ME Identity for emergency
     * attached UE without UICC or authenticated IMSI), this Create Session
     * Request shall be treated as a request for a new session. Before creating
     * the new session, the UPF should delete:
     *
     * - the existing PDN connection context, if the Create Session Request
     *   collides with the default bearer of an existing PDN connection context;
     * - the existing dedicated bearer context, if the Create Session Request
     *   collides with a dedicated bearer of an existing PDN connection context.
     */
    sess = upf_sess_find_by_imsi_apn(req->imsi.data, req->imsi.len, apn);
    if (sess) {
        ogs_warn("OLD Session Release [IMSI:%s,APN:%s]",
                sess->imsi_bcd, sess->pdn.apn);
        upf_sess_remove(sess);
    }
    sess = upf_sess_add(req->imsi.data, req->imsi.len, apn,
                    req->pdn_type.u8,
                    req->bearer_contexts_to_be_created.eps_bearer_id.u8, paa);
    ogs_assert(sess);

    return sess;
}

upf_bearer_t *upf_bearer_add(upf_sess_t *sess)
{
    upf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    ogs_pool_alloc(&upf_bearer_pool, &bearer);
    ogs_assert(bearer);
    memset(bearer, 0, sizeof *bearer);

    bearer->index = ogs_pool_index(&upf_bearer_pool, bearer);
    ogs_assert(bearer->index > 0 && bearer->index <=
            ogs_config()->pool.bearer);

    ogs_list_init(&bearer->pf_list);

    bearer->upf_s5u_teid = bearer->index;
    
    bearer->sess = sess;

    ogs_list_add(&sess->bearer_list, bearer);

    return bearer;
}

int upf_bearer_remove(upf_bearer_t *bearer)
{
    ogs_assert(bearer);
    ogs_assert(bearer->sess);

    ogs_list_remove(&bearer->sess->bearer_list, bearer);

    if (bearer->name)
        ogs_free(bearer->name);

    upf_pf_remove_all(bearer);

    ogs_pool_free(&upf_bearer_pool, bearer);

    return OGS_OK;
}

void upf_bearer_remove_all(upf_sess_t *sess)
{
    upf_bearer_t *bearer = NULL, *next_bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each_safe(&sess->bearer_list, next_bearer, bearer)
        upf_bearer_remove(bearer);
}

upf_bearer_t *upf_bearer_find(uint32_t index)
{
    ogs_assert(index);
    return ogs_pool_find(&upf_bearer_pool, index);
}

upf_bearer_t *upf_bearer_find_by_upf_s5u_teid(uint32_t upf_s5u_teid)
{
    return upf_bearer_find(upf_s5u_teid);
}

upf_bearer_t *upf_bearer_find_by_ebi(upf_sess_t *sess, uint8_t ebi)
{
    upf_bearer_t *bearer = NULL;
    
    ogs_assert(sess);

    bearer = upf_bearer_first(sess);
    while (bearer) {
        if (bearer->ebi == ebi)
            break;

        bearer = upf_bearer_next(bearer);
    }

    return bearer;
}

upf_bearer_t *upf_bearer_find_by_name(upf_sess_t *sess, char *name)
{
    upf_bearer_t *bearer = NULL;
    
    ogs_assert(sess);
    ogs_assert(name);

    bearer = upf_bearer_first(sess);
    while (bearer) {
        if (bearer->name && strcmp(bearer->name, name) == 0)
            return bearer;

        bearer = upf_bearer_next(bearer);
    }

    return NULL;
}

upf_bearer_t *upf_bearer_find_by_qci_arp(upf_sess_t *sess, 
                                uint8_t qci,
                                uint8_t priority_level,
                                uint8_t pre_emption_capability,
                                uint8_t pre_emption_vulnerability)
{
    upf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    bearer = upf_default_bearer_in_sess(sess);
    if (!bearer) return NULL;

    if (sess->pdn.qos.qci == qci &&
        sess->pdn.qos.arp.priority_level == priority_level &&
        sess->pdn.qos.arp.pre_emption_capability == 
            pre_emption_capability &&
        sess->pdn.qos.arp.pre_emption_vulnerability == 
            pre_emption_vulnerability) {
        return bearer;
    }

    bearer = upf_bearer_next(bearer);
    while (bearer) {
        if (bearer->qos.qci == qci &&
            bearer->qos.arp.priority_level == priority_level &&
            bearer->qos.arp.pre_emption_capability == 
                pre_emption_capability &&
            bearer->qos.arp.pre_emption_vulnerability == 
                pre_emption_vulnerability) {
            return bearer;
        }
        bearer = upf_bearer_next(bearer);
    }

    return NULL;
}

upf_bearer_t *upf_default_bearer_in_sess(upf_sess_t *sess)
{
    return upf_bearer_first(sess);
}

upf_bearer_t *upf_bearer_first(upf_sess_t *sess)
{
    ogs_assert(sess);
    return ogs_list_first(&sess->bearer_list);
}

upf_bearer_t *upf_bearer_next(upf_bearer_t *bearer)
{
    return ogs_list_next(bearer);
}

upf_pf_t *upf_pf_add(upf_bearer_t *bearer, uint32_t precedence)
{
    upf_pf_t *pf = NULL;

    ogs_assert(bearer);

    ogs_pool_alloc(&upf_pf_pool, &pf);
    ogs_assert(pf);
    memset(pf, 0, sizeof *pf);

    pf->identifier = OGS_NEXT_ID(bearer->pf_identifier, 1, 15);
    pf->bearer = bearer;

    ogs_list_add(&bearer->pf_list, pf);

    return pf;
}

int upf_pf_remove(upf_pf_t *pf)
{
    ogs_assert(pf);
    ogs_assert(pf->bearer);

    ogs_list_remove(&pf->bearer->pf_list, pf);
    ogs_pool_free(&upf_pf_pool, pf);

    return OGS_OK;
}

void upf_pf_remove_all(upf_bearer_t *bearer)
{
    upf_pf_t *pf = NULL, *next_pf = NULL;

    ogs_assert(bearer);
    ogs_list_for_each_safe(&bearer->pf_list, next_pf, pf)
        upf_pf_remove(pf);
}

upf_pf_t *upf_pf_find_by_id(upf_bearer_t *bearer, uint8_t id)
{
    upf_pf_t *pf = NULL;
    
    pf = upf_pf_first(bearer);
    while (pf) {
        if (pf->identifier == id)
            return pf;

        pf = upf_pf_next(pf);
    }

    return OGS_OK;
}

upf_pf_t *upf_pf_first(upf_bearer_t *bearer)
{
    return ogs_list_first(&bearer->pf_list);
}

upf_pf_t *upf_pf_next(upf_pf_t *pf)
{
    return ogs_list_next(pf);
}

int upf_ue_pool_generate(void)
{
    int i, rv;
    upf_subnet_t *subnet = NULL;

    for (subnet = upf_subnet_first(); 
        subnet; subnet = upf_subnet_next(subnet)) {
        int maxbytes = 0;
        int lastindex = 0;
        uint32_t start[4], end[4], broadcast[4];
        int rangeindex, num_of_range;
        int poolindex;
        int inc;

        if (subnet->family == AF_INET) {
            maxbytes = 4;
            lastindex = 0;
        }
        else if (subnet->family == AF_INET6) {
            maxbytes = 16;
            lastindex = 3;
        }

        for (i = 0; i < 4; i++) {
            broadcast[i] = subnet->sub.sub[i] + ~subnet->sub.mask[i];
        }

        num_of_range = subnet->num_of_range;
        if (!num_of_range) num_of_range = 1;

        poolindex = 0;
        for (rangeindex = 0; rangeindex < num_of_range; rangeindex++) {

            if (subnet->num_of_range &&
                subnet->range[rangeindex].low) {
                ogs_ipsubnet_t low;
                rv = ogs_ipsubnet(
                        &low, subnet->range[rangeindex].low, NULL);
                ogs_assert(rv == OGS_OK);
                memcpy(start, low.sub, maxbytes);
            } else {
                memcpy(start, subnet->sub.sub, maxbytes);
            }

            if (subnet->num_of_range &&
                subnet->range[rangeindex].high) {
                ogs_ipsubnet_t high;
                rv = ogs_ipsubnet(
                        &high, subnet->range[rangeindex].high, NULL);
                ogs_assert(rv == OGS_OK);
                high.sub[lastindex] += htobe32(1);
                memcpy(end, high.sub, maxbytes);
            } else {
                memcpy(end, broadcast, maxbytes);
            }

            inc = 0;
            while(poolindex < ogs_config()->pool.sess) {
                upf_ue_ip_t *ue_ip = NULL;

                ue_ip = &subnet->pool.array[poolindex];
                ogs_assert(ue_ip);
                memset(ue_ip, 0, sizeof *ue_ip);
                ue_ip->subnet = subnet;

                memcpy(ue_ip->addr, start, maxbytes);
                ue_ip->addr[lastindex] += htobe32(inc);
                inc++;

                if (memcmp(ue_ip->addr, end, maxbytes) == 0)
                    break;

                /* Exclude Network Address */
                if (memcmp(ue_ip->addr, subnet->sub.sub, maxbytes) == 0)
                    continue;

                /* Exclude TUN IP Address */
                if (memcmp(ue_ip->addr, subnet->gw.sub, maxbytes) == 0)
                    continue;

                ogs_trace("[%d] - %x:%x:%x:%x",
                        poolindex,
                        ue_ip->addr[0], ue_ip->addr[1],
                        ue_ip->addr[2], ue_ip->addr[3]);

                poolindex++;
            }
        }
        subnet->pool.size = subnet->pool.avail = poolindex;
    }

    return OGS_OK;
}

static upf_subnet_t *find_subnet(int family, const char *apn)
{
    upf_subnet_t *subnet = NULL;

    ogs_assert(apn);
    ogs_assert(family == AF_INET || family == AF_INET6);

    for (subnet = upf_subnet_first();
            subnet; subnet = upf_subnet_next(subnet)) {
        if (strlen(subnet->apn)) {
            if (subnet->family == family && strcmp(subnet->apn, apn) == 0 &&
                ogs_pool_avail(&subnet->pool)) {
                return subnet;
            }
        }
    }

    for (subnet = upf_subnet_first();
            subnet; subnet = upf_subnet_next(subnet)) {
        if (strlen(subnet->apn) == 0) {
            if (subnet->family == family &&
                ogs_pool_avail(&subnet->pool)) {
                return subnet;
            }
        }
    }

    if (subnet == NULL)
        ogs_error("CHECK CONFIGURATION: Cannot find UE Pool");

    return subnet;
}

upf_ue_ip_t *upf_ue_ip_alloc(int family, const char *apn, uint8_t *addr)
{
    upf_subnet_t *subnet = NULL;
    upf_ue_ip_t *ue_ip = NULL;

    uint8_t zero[16];
    size_t maxbytes = 0;

    ogs_assert(apn);
    subnet = find_subnet(family, apn);
    ogs_assert(subnet);

    memset(zero, 0, sizeof zero);
    if (family == AF_INET) {
        maxbytes = 4;
    } else if (family == AF_INET6) {
        maxbytes = 16;
    } else {
        ogs_fatal("Invalid family[%d]", family);
        ogs_assert_if_reached();
    }

    // if assigning a static IP, do so. If not, assign dynamically!
    if (memcmp(addr, zero, maxbytes) != 0) {
        ue_ip = ogs_calloc(1, sizeof(upf_ue_ip_t));

        ue_ip->subnet = subnet;
        ue_ip->static_ip = true;
        memcpy(ue_ip->addr, addr, maxbytes);
    } else {
        ogs_pool_alloc(&subnet->pool, &ue_ip);
    }

    ogs_assert(ue_ip);
    return ue_ip;
}

int upf_ue_ip_free(upf_ue_ip_t *ue_ip)
{
    upf_subnet_t *subnet = NULL;

    ogs_assert(ue_ip);
    subnet = ue_ip->subnet;

    ogs_assert(subnet);

    if (ue_ip->static_ip) {
        ogs_free(ue_ip);
    } else {
        ogs_pool_free(&subnet->pool, ue_ip);
    }

    return OGS_OK;
}

upf_dev_t *upf_dev_add(const char *ifname)
{
    upf_dev_t *dev = NULL;

    ogs_assert(ifname);

    ogs_pool_alloc(&upf_dev_pool, &dev);
    ogs_assert(dev);
    memset(dev, 0, sizeof *dev);

    strcpy(dev->ifname, ifname);

    ogs_list_add(&self.dev_list, dev);

    return dev;
}

int upf_dev_remove(upf_dev_t *dev)
{
    ogs_assert(dev);

    ogs_list_remove(&self.dev_list, dev);

    if (dev->link_local_addr)
        ogs_freeaddrinfo(dev->link_local_addr);

    ogs_pool_free(&upf_dev_pool, dev);

    return OGS_OK;
}

void upf_dev_remove_all(void)
{
    upf_dev_t *dev = NULL, *next_dev = NULL;

    ogs_list_for_each_safe(&self.dev_list, next_dev, dev)
        upf_dev_remove(dev);
}

upf_dev_t *upf_dev_find_by_ifname(const char *ifname)
{
    upf_dev_t *dev = NULL;

    ogs_assert(ifname);
    
    dev = upf_dev_first();
    while (dev) {
        if (strcmp(dev->ifname, ifname) == 0)
            return dev;

        dev = upf_dev_next(dev);
    }

    return OGS_OK;
}

upf_dev_t *upf_dev_first(void)
{
    return ogs_list_first(&self.dev_list);
}

upf_dev_t *upf_dev_next(upf_dev_t *dev)
{
    return ogs_list_next(dev);
}

upf_subnet_t *upf_subnet_add(
        const char *ipstr, const char *mask_or_numbits,
        const char *apn, const char *ifname)
{
    int rv;
    upf_dev_t *dev = NULL;
    upf_subnet_t *subnet = NULL;

    ogs_assert(ipstr);
    ogs_assert(mask_or_numbits);
    ogs_assert(ifname);

    dev = upf_dev_find_by_ifname(ifname);
    if (!dev)
        dev = upf_dev_add(ifname);
    ogs_assert(dev);

    ogs_pool_alloc(&upf_subnet_pool, &subnet);
    ogs_assert(subnet);
    memset(subnet, 0, sizeof *subnet);

    subnet->dev = dev;

    rv = ogs_ipsubnet(&subnet->gw, ipstr, NULL);
    ogs_assert(rv == OGS_OK);

    rv = ogs_ipsubnet(&subnet->sub, ipstr, mask_or_numbits);
    ogs_assert(rv == OGS_OK);

    if (apn)
        strcpy(subnet->apn, apn);

    subnet->family = subnet->gw.family;
    subnet->prefixlen = atoi(mask_or_numbits);

    ogs_pool_init(&subnet->pool, ogs_config()->pool.sess);

    ogs_list_add(&self.subnet_list, subnet);

    return subnet;
}

int upf_subnet_remove(upf_subnet_t *subnet)
{
    ogs_assert(subnet);

    ogs_list_remove(&self.subnet_list, subnet);

    ogs_pool_final(&subnet->pool);

    ogs_pool_free(&upf_subnet_pool, subnet);

    return OGS_OK;
}

void upf_subnet_remove_all(void)
{
    upf_subnet_t *subnet = NULL, *next_subnet = NULL;

    ogs_list_for_each_safe(&self.subnet_list, next_subnet, subnet)
        upf_subnet_remove(subnet);
}

upf_subnet_t *upf_subnet_first(void)
{
    return ogs_list_first(&self.subnet_list);
}

upf_subnet_t *upf_subnet_next(upf_subnet_t *subnet)
{
    return ogs_list_next(subnet);
}
