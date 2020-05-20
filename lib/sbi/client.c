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

#include "ogs-app.h"
#include "ogs-sbi.h"

#include "sbi-private.h"
#include "curl/curl.h"

typedef struct sockinfo_s {
    ogs_poll_t *poll;
    curl_socket_t sockfd;
    int action;
    CURL *easy;
    ogs_sbi_client_t *client;
} sockinfo_t;

typedef struct connection_s {
    ogs_lnode_t lnode;

    void *data;

    char *method;

    int num_of_header;
    char **headers;
    struct curl_slist *header_list;

    char *memory;
    size_t size;

    ogs_timer_t *timer;
    CURL *easy;
    char error[CURL_ERROR_SIZE];

    ogs_sbi_client_t *client;
} connection_t;

static OGS_POOL(client_pool, ogs_sbi_client_t);
static OGS_POOL(sockinfo_pool, sockinfo_t);
static OGS_POOL(connection_pool, connection_t);

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *data);
static int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp);
static int multi_timer_cb(CURLM *multi, long timeout_ms, void *cbp);
static void multi_timer_expired(void *data);
static void connection_timer_expired(void *data);
static void connection_remove_all(ogs_sbi_client_t *client);

void ogs_sbi_client_init(int num_of_sockinfo_pool, int num_of_connection_pool)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    ogs_list_init(&ogs_sbi_self()->client_list);
    ogs_pool_init(&client_pool, ogs_config()->pool.sbi);

    ogs_pool_init(&sockinfo_pool, num_of_sockinfo_pool);
    ogs_pool_init(&connection_pool, num_of_connection_pool);

}
void ogs_sbi_client_final(void)
{
    ogs_sbi_client_remove_all();

    ogs_pool_final(&client_pool);
    ogs_pool_final(&sockinfo_pool);
    ogs_pool_final(&connection_pool);

    curl_global_cleanup();
}

ogs_sbi_client_t *ogs_sbi_client_add(ogs_sockaddr_t *addr)
{
    ogs_sbi_client_t *client = NULL;
    CURLM *multi = NULL;

    ogs_assert(addr);

    ogs_pool_alloc(&client_pool, &client);
    ogs_assert(client);
    memset(client, 0, sizeof(ogs_sbi_client_t));

    ogs_copyaddrinfo(&client->addr, addr);

    ogs_list_init(&client->connection_list);

    client->t_curl = ogs_timer_add(
            ogs_sbi_self()->timer_mgr, multi_timer_expired, client);

    multi = client->multi = curl_multi_init();
    ogs_assert(multi);
    curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
    curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, client);
    curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
    curl_multi_setopt(multi, CURLMOPT_TIMERDATA, client);

    ogs_list_add(&ogs_sbi_self()->client_list, client);

    return client;
}

ogs_sbi_client_t *ogs_sbi_client_find_or_add(char *url)
{
    int rv;

    ogs_sbi_client_t *client = NULL;
    struct yuarel yuarel;
    char *p = ogs_strdup(url);
    int port;

    ogs_sockaddr_t *addr = NULL;

    rv = yuarel_parse(&yuarel, p);
    if (rv != OGS_OK) {
        ogs_free(p);
        ogs_error("yuarel_parse() failed [%s]", url);
        return NULL;
    }

    if (!yuarel.scheme) {
        ogs_error("No http.scheme found [%s]", url);
        ogs_free(p);
        return NULL;
    }

    if (strcmp(yuarel.scheme, "https") == 0) {
        port = OGS_SBI_HTTPS_PORT;
    } else if (strcmp(yuarel.scheme, "http") == 0) {
        port = OGS_SBI_HTTP_PORT;
    } else {
        ogs_error("Invalid http.scheme [%s:%s]", yuarel.scheme, url);
        ogs_free(p);
        return NULL;
    }

    if (!yuarel.host) {
        ogs_error("No http.host found [%s]", url);
        ogs_free(p);
        return NULL;
    }

    if (yuarel.port) port = yuarel.port;

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC, yuarel.host, port, 0);
    if (rv != OGS_OK) {
        ogs_error("ogs_getaddrinfo() failed [%s]", url);
        ogs_free(p);
    }

    client = ogs_sbi_client_find(addr);
    if (!client) {
        client = ogs_sbi_client_add(addr);
        ogs_assert(client);
    }

    ogs_freeaddrinfo(addr);
    ogs_free(p);

    return client;
}

void ogs_sbi_client_remove(ogs_sbi_client_t *client)
{
    ogs_assert(client);

    ogs_list_remove(&ogs_sbi_self()->client_list, client);

    connection_remove_all(client);

    ogs_assert(client->t_curl);
    ogs_timer_delete(client->t_curl);

    ogs_assert(client->multi);
    curl_multi_cleanup(client->multi);

    ogs_assert(client->addr);
    ogs_freeaddrinfo(client->addr);

    ogs_pool_free(&client_pool, client);
}

void ogs_sbi_client_remove_all(void)
{
    ogs_sbi_client_t *client = NULL, *next_client = NULL;

    ogs_list_for_each_safe(&ogs_sbi_self()->client_list, next_client, client)
        ogs_sbi_client_remove(client);
}

ogs_sbi_client_t *ogs_sbi_client_find(ogs_sockaddr_t *addr)
{
    ogs_sbi_client_t *client = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&ogs_sbi_self()->client_list, client) {
        if (ogs_sockaddr_is_equal(client->addr, addr) == true)
            break;
    }

    return client;
}

#define mycase(code) \
  case code: s = __STRING(code)

static void mcode_or_die(const char *where, CURLMcode code)
{
    if(CURLM_OK != code) {
        const char *s;
        switch(code) {
            mycase(CURLM_BAD_HANDLE); break;
            mycase(CURLM_BAD_EASY_HANDLE); break;
            mycase(CURLM_OUT_OF_MEMORY); break;
            mycase(CURLM_INTERNAL_ERROR); break;
            mycase(CURLM_UNKNOWN_OPTION); break;
            mycase(CURLM_LAST); break;
            default: s = "CURLM_unknown"; break;
            mycase(CURLM_BAD_SOCKET);
            ogs_error("ERROR: %s returns %s", where, s);
            /* ignore this error */
            return;
        }
        ogs_fatal("ERROR: %s returns %s", where, s);
        ogs_assert_if_reached();
    }
}

static char *add_params_to_url(CURL *easy, char *url, ogs_hash_t *params)
{
    ogs_hash_index_t *hi;
    int has_params = 0;
    const char *fp = "?", *np = "&";

    ogs_assert(easy);
    ogs_assert(url);
    ogs_assert(params);
    ogs_assert(ogs_hash_count(params));

    has_params = (strchr(url, '?') != NULL);

    for (hi = ogs_hash_first(params); hi; hi = ogs_hash_next(hi)) {
        const char *key = NULL;
        char *key_esc = NULL;
        char *val = NULL;
        char *val_esc = NULL;

        key = ogs_hash_this_key(hi);
        ogs_assert(key);
        val = ogs_hash_this_val(hi);
        ogs_assert(val);

        key_esc = curl_easy_escape(easy, key, 0);
        ogs_assert(key_esc);
        val_esc = curl_easy_escape(easy, val, 0);
        ogs_assert(val_esc);

        if (!has_params) {
            url = ogs_mstrcatf(url, "%s%s=%s", fp, key_esc, val_esc);
            has_params = 1;
        } else {
            url = ogs_mstrcatf(url, "%s%s=%s", np, key_esc, val_esc);
        }

        curl_free(val_esc);
        curl_free(key_esc);
    }

    return url;
}

static connection_t *connection_add(ogs_sbi_client_t *client,
        ogs_sbi_request_t *request, void *data)
{
    ogs_hash_index_t *hi;
    int i;
    connection_t *conn = NULL;
    CURLMcode rc;

    ogs_assert(client);
    ogs_assert(request);

    ogs_pool_alloc(&connection_pool, &conn);
    ogs_assert(conn);
    memset(conn, 0, sizeof(connection_t));

    ogs_assert(request->h.method);
    conn->method = ogs_strdup(request->h.method);

    conn->num_of_header = ogs_hash_count(request->http.headers);
    if (conn->num_of_header) {
        conn->headers = ogs_calloc(conn->num_of_header, sizeof(char *));
        ogs_assert(conn->headers);
        for (hi = ogs_hash_first(request->http.headers), i = 0;
                hi && i < conn->num_of_header; hi = ogs_hash_next(hi), i++) {
            const char *key = ogs_hash_this_key(hi);
            char *val = ogs_hash_this_val(hi);

            conn->headers[i] = ogs_msprintf("%s: %s", key, val);
            ogs_assert(conn->headers[i]);
            conn->header_list = curl_slist_append(
                    conn->header_list, conn->headers[i]);
        }
    }

    conn->timer = ogs_timer_add(
            ogs_sbi_self()->timer_mgr, connection_timer_expired, conn);
    ogs_assert(conn->timer);

    /* If http response is not received within 1 second,
     * we will discard this request. */
    ogs_timer_start(conn->timer, ogs_time_from_sec(1));

    conn->easy = curl_easy_init();
    ogs_assert(conn->easy);

    /* HTTP Method */
    if (strcmp(request->h.method, OGS_SBI_HTTP_METHOD_PUT) == 0 ||
        strcmp(request->h.method, OGS_SBI_HTTP_METHOD_PATCH) == 0 ||
        strcmp(request->h.method, OGS_SBI_HTTP_METHOD_DELETE) == 0 ||
        strcmp(request->h.method, OGS_SBI_HTTP_METHOD_POST) == 0) {

        curl_easy_setopt(conn->easy, CURLOPT_CUSTOMREQUEST, request->h.method);
        if (request->http.content) {
            curl_easy_setopt(conn->easy, CURLOPT_HTTPHEADER, conn->header_list);
            curl_easy_setopt(conn->easy, CURLOPT_POSTFIELDS,
                    request->http.content);
        }
    }

    if (ogs_hash_count(request->http.params)) {
        request->h.url = add_params_to_url(conn->easy,
                            request->h.url, request->http.params);
    }

    curl_easy_setopt(conn->easy, CURLOPT_URL, request->h.url);

    curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
    curl_easy_setopt(conn->easy, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(conn->easy, CURLOPT_WRITEDATA, conn);
    curl_easy_setopt(conn->easy, CURLOPT_ERRORBUFFER, conn->error);

    ogs_assert(client->multi);
    rc = curl_multi_add_handle(client->multi, conn->easy);
    mcode_or_die("connection_add: curl_multi_add_handle", rc);

    conn->client = client;
    conn->data = data;

    ogs_list_add(&client->connection_list, conn);

    return conn;
}

static void connection_remove(connection_t *conn)
{
    ogs_sbi_client_t *client = NULL;
    int i;

    ogs_assert(conn);
    client = conn->client;
    ogs_assert(client);

    ogs_list_remove(&client->connection_list, conn);

    ogs_assert(conn->timer);
    ogs_timer_delete(conn->timer);

    ogs_assert(conn->easy);
    ogs_assert(client->multi);
    curl_multi_remove_handle(client->multi, conn->easy);
    curl_easy_cleanup(conn->easy);

    ogs_assert(conn->method);
    ogs_free(conn->method);

    if (conn->num_of_header) {
        for (i = 0; i < conn->num_of_header; i++)
            ogs_free(conn->headers[i]);
        ogs_free(conn->headers);
    }
    curl_slist_free_all(conn->header_list);

    if (conn->memory)
        ogs_free(conn->memory);

    ogs_pool_free(&connection_pool, conn);
}

static void connection_remove_all(ogs_sbi_client_t *client)
{
    connection_t *conn = NULL, *next_conn = NULL;

    ogs_assert(client);

    ogs_list_for_each_safe(&client->connection_list, next_conn, conn)
        connection_remove(conn);
}

static void connection_timer_expired(void *data)
{
    connection_t *conn = NULL;

    conn = data;
    ogs_assert(conn);

    connection_remove(conn);
}

static void check_multi_info(ogs_sbi_client_t *client)
{
    CURLM *multi = NULL;
    CURLMsg *resource;
    int pending;
    CURL *easy = NULL;
    CURLcode res;
    connection_t *conn = NULL;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(client);
    multi = client->multi;
    ogs_assert(multi);

    while ((resource = curl_multi_info_read(multi, &pending))) {
        char *url;
        char *content_type = NULL;
        long res_status;
        ogs_assert(resource);

        switch (resource->msg) {
        case CURLMSG_DONE:
            easy = resource->easy_handle;
            ogs_assert(easy);

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &conn);
            ogs_assert(conn);

            curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &res_status);
            curl_easy_getinfo(easy, CURLINFO_CONTENT_TYPE, &content_type);

            res = resource->data.result;
            if (res == CURLE_OK) {
                response = ogs_sbi_response_new();
                ogs_assert(response);

                response->status = res_status;

                ogs_assert(conn->method);
                response->h.method = ogs_strdup(conn->method);

                /* remove https://localhost:8000 */
                response->h.url = ogs_strdup(url);

                response->http.content = ogs_strdup(conn->memory);
                response->http.content_length = conn->size;

                if (content_type)
                    ogs_sbi_header_set(response->http.headers,
                            "Content-Type", content_type);

                if (client->cb) 
                    client->cb(response, conn->data);
                else {
                    ogs_fatal("client callback is not registered");
                    ogs_sbi_response_free(response);
                    ogs_assert_if_reached();
                }
            } else
                ogs_warn("[%d] %s", res, conn->error);

            connection_remove(conn);
            break;
        default:
            ogs_error("Unknown CURL resource[%d]", resource->msg);
            break;
        }
    }
}

void ogs_sbi_client_send_request(
        ogs_sbi_client_t *client, ogs_sbi_request_t *request, void *data)
{
    connection_t *conn = NULL;

    ogs_assert(client);
    ogs_assert(request);

    if (request->h.url == NULL) {
        request->h.url = ogs_sbi_client_uri(client,
                request->h.service.name, request->h.api.version,
                request->h.resource.name, request->h.resource.id);
    }

    conn = connection_add(client, request, data);
    ogs_assert(conn);
    ogs_sbi_request_free(request);
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *data)
{
    size_t realsize = 0;
    connection_t *conn = NULL;
    char *ptr = NULL;

    conn = data;
    ogs_assert(conn);

    realsize = size * nmemb;
    ptr = ogs_realloc(conn->memory, conn->size + realsize + 1);
    if(!ptr) {
        ogs_fatal("not enough memory (realloc returned NULL)");
        return 0;
    }

    conn->memory = ptr;
    memcpy(&(conn->memory[conn->size]), contents, realsize);
    conn->size += realsize;
    conn->memory[conn->size] = 0;

    return realsize;
}

static void event_cb(short when, ogs_socket_t fd, void *data)
{
    sockinfo_t *sockinfo = NULL;
    ogs_sbi_client_t *client = NULL;
    CURLM *multi = NULL;

    CURLMcode rc;
    int action = ((when & OGS_POLLIN) ? CURL_CSELECT_IN : 0) |
                    ((when & OGS_POLLOUT) ? CURL_CSELECT_OUT : 0);

    sockinfo = data;
    ogs_assert(sockinfo);
    client = sockinfo->client;
    ogs_assert(client);
    multi = client->multi;
    ogs_assert(multi);

    rc = curl_multi_socket_action(multi, fd, action, &client->still_running);
    mcode_or_die("event_cb: curl_multi_socket_action", rc);

    check_multi_info(client);
    if (client->still_running <= 0) {
        ogs_timer_t *timer;

        timer = client->t_curl;
        ogs_assert(timer);
        ogs_timer_stop(timer);
    }
}

/* Assign information to a sockinfo_t structure */
static void sock_set(sockinfo_t *sockinfo, curl_socket_t s,
        CURL *e, int act, ogs_sbi_client_t *client)
{
    int kind = ((act & CURL_POLL_IN) ? OGS_POLLIN : 0) |
                ((act & CURL_POLL_OUT) ? OGS_POLLOUT : 0);

    if (sockinfo->sockfd)
        ogs_pollset_remove(sockinfo->poll);

    sockinfo->sockfd = s;
    sockinfo->action = act;
    sockinfo->easy = e;

    sockinfo->poll = ogs_pollset_add(
            ogs_sbi_self()->pollset, kind, s, event_cb, sockinfo);
}

/* Initialize a new sockinfo_t structure */
static void sock_new(curl_socket_t s,
        CURL *easy, int action, ogs_sbi_client_t *client)
{
    sockinfo_t *sockinfo = NULL;
    CURLM *multi = NULL;

    ogs_assert(client);
    multi = client->multi;
    ogs_assert(multi);

    ogs_pool_alloc(&sockinfo_pool, &sockinfo);
    ogs_assert(sockinfo);
    memset(sockinfo, 0, sizeof(sockinfo_t));

    sockinfo->client = client;
    sock_set(sockinfo, s, easy, action, client);
    curl_multi_assign(multi, s, sockinfo);
}

/* Clean up the sockinfo_t structure */
static void sock_free(sockinfo_t *sockinfo, ogs_sbi_client_t *client)
{
    ogs_assert(sockinfo);
    ogs_assert(sockinfo->poll);

    ogs_pollset_remove(sockinfo->poll);
    ogs_pool_free(&sockinfo_pool, sockinfo);
}

/* CURLMOPT_SOCKETFUNCTION */
static int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
    ogs_sbi_client_t *client = (ogs_sbi_client_t *)cbp;
    sockinfo_t *sockinfo = (sockinfo_t *) sockp;

    if (what == CURL_POLL_REMOVE) {
        sock_free(sockinfo, client);
    } else {
        if (!sockinfo) {
            sock_new(s, e, what, client);
        } else {
            sock_set(sockinfo, s, e, what, client);
        }
    }
    return 0;
}

static void multi_timer_expired(void *data)
{
    CURLMcode rc;
    ogs_sbi_client_t *client = NULL;
    CURLM *multi = NULL;

    client = data;
    ogs_assert(client);
    multi = client->multi;
    ogs_assert(multi);

    rc = curl_multi_socket_action(
            multi, CURL_SOCKET_TIMEOUT, 0, &client->still_running);
    mcode_or_die("multi_timer_expired: curl_multi_socket_action", rc);
    check_multi_info(client);
}

static int multi_timer_cb(CURLM *multi, long timeout_ms, void *cbp)
{
    ogs_sbi_client_t *client = NULL;
    ogs_timer_t *timer = NULL;

    client = cbp;
    ogs_assert(client);
    timer = client->t_curl;
    ogs_assert(timer);

    if (timeout_ms > 0) {
        ogs_timer_start(timer, ogs_time_from_msec(timeout_ms));
    } else if (timeout_ms == 0) {
        /* libcurl wants us to timeout now.
         * The closest we can do is to schedule the timer to fire in 1 us. */
        ogs_timer_start(timer, 1);
    } else {
        ogs_timer_stop(timer);
    }

    return 0;
}
