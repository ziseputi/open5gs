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

#include "nnrf-handler.h"

bool nrf_nnrf_handle_nf_register(
        ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *message)
{
    int status;
    bool handled;
    ogs_sbi_response_t *response = NULL;

    OpenAPI_nf_profile_t *NFProfile = NULL;

    ogs_assert(nf_instance);
    ogs_assert(session);
    ogs_assert(message);

    NFProfile = message->NFProfile;
    if (!NFProfile) {
        ogs_error("No NFProfile");
        ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No NFProfile", NULL);
        return false;
    }

    /* ogs_sbi_nnrf_handle_nf_profile() sends error response */
    handled = ogs_sbi_nnrf_handle_nf_profile(
                nf_instance, NFProfile, session, message);
    if (!handled) return false;

    if (OGS_FSM_CHECK(&nf_instance->sm, nrf_nf_state_will_register)) {
        message->http.location = true;
        status = OGS_SBI_HTTP_STATUS_CREATED;
    } else if (OGS_FSM_CHECK(&nf_instance->sm, nrf_nf_state_registered)) {
        status = OGS_SBI_HTTP_STATUS_OK;
    } else
        ogs_assert_if_reached();

    response = ogs_sbi_build_response(message);
    ogs_assert(response);
    ogs_sbi_server_send_response(session, response, status);

    return true;
}

bool nrf_nnrf_handle_nf_update(
        ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *message)
{
    ogs_sbi_response_t *response = NULL;
    OpenAPI_list_t *PatchItemList = NULL;
    OpenAPI_lnode_t *node;

    ogs_assert(nf_instance);
    ogs_assert(session);
    ogs_assert(message);

    SWITCH(message->h.method)
    CASE(OGS_SBI_HTTP_METHOD_PUT)
        return nrf_nnrf_handle_nf_register(
                nf_instance, server, session, message);

    CASE(OGS_SBI_HTTP_METHOD_PATCH)
        PatchItemList = message->PatchItemList;
        if (!PatchItemList) {
            ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    message, "No PatchItemList Array", NULL);
            return false;
        }

        OpenAPI_list_for_each(PatchItemList, node) {
            OpenAPI_patch_item_t *patch_item = node->data;
            if (!patch_item) {
                ogs_sbi_server_send_error(session,
                        OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        message, "No PatchItemList", NULL);
                return false;
            }
        }

        response = ogs_sbi_build_response(message);
        ogs_assert(response);
        ogs_sbi_server_send_response(session, response,
                OGS_SBI_HTTP_STATUS_NO_CONTENT);
        break;

    DEFAULT
        ogs_error("Invalid HTTP method [%s]",
                message->h.method);
        ogs_assert_if_reached();
    END

    return true;
}

bool nrf_nnrf_handle_nf_status_subscribe(ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *message)
{
    int status;
    ogs_sbi_response_t *response = NULL;
    OpenAPI_subscription_data_t *SubscriptionData = NULL;
    ogs_sbi_subscription_t *subscription = NULL;
    ogs_sbi_client_t *client = NULL;
    ogs_sockaddr_t *addr = NULL;

    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];

    ogs_assert(session);
    ogs_assert(message);

    SubscriptionData = message->SubscriptionData;
    if (!SubscriptionData) {
        ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No SubscriptionData", NULL);
        return false;
    }

    if (!SubscriptionData->nf_status_notification_uri) {
        ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No SubscriptionData", "NFStatusNotificationURL");
        return false;
    }

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    subscription = ogs_sbi_subscription_add();
    ogs_assert(subscription);
    ogs_sbi_subscription_set_id(subscription, id);
    ogs_assert(subscription->id);

    if (SubscriptionData->req_nf_instance_id)
        subscription->nf_instance_id =
            ogs_strdup(SubscriptionData->req_nf_instance_id);

    if (SubscriptionData->subscription_id) {
        ogs_warn("NF should not send SubscriptionID[%s]",
                SubscriptionData->subscription_id);
        ogs_free(SubscriptionData->subscription_id);
    }
    SubscriptionData->subscription_id = ogs_strdup(subscription->id);

    subscription->notification_uri =
            ogs_strdup(SubscriptionData->nf_status_notification_uri);
    ogs_assert(subscription->notification_uri);

    addr = ogs_sbi_getaddr_from_uri(subscription->notification_uri);
    if (!addr) {
        ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "Invalid URI", subscription->notification_uri);
        return false;
    }

    client = ogs_sbi_client_find(addr);
    if (!client) {
        client = ogs_sbi_client_add(addr);
        ogs_assert(client);
    }
    OGS_SETUP_SBI_CLIENT(subscription, client);

    ogs_freeaddrinfo(addr);

    if (subscription->time.validity) {
        char buf[OGS_TIME_ISO8601_FORMATTED_LENGTH];
        struct timeval tv;
        struct tm local;

        ogs_gettimeofday(&tv);
        tv.tv_sec += subscription->time.validity;
        ogs_localtime(tv.tv_sec, &local);

        ogs_strftime(buf, OGS_TIME_ISO8601_FORMATTED_LENGTH,
                OGS_TIME_ISO8601_FORMAT, &local);

        SubscriptionData->validity_time = ogs_strdup(buf);

        subscription->t_validity = ogs_timer_add(nrf_self()->timer_mgr,
            nrf_timer_subscription_validity, subscription);
        ogs_assert(subscription->t_validity);
        ogs_timer_start(subscription->t_validity,
                ogs_time_from_sec(subscription->time.validity));
    }

    message->http.location = true;
    status = OGS_SBI_HTTP_STATUS_CREATED;

    response = ogs_sbi_build_response(message);
    ogs_assert(response);
    ogs_sbi_server_send_response(session, response, status);

    return true;
}

bool nrf_nnrf_handle_nf_status_unsubscribe(ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *message)
{
    ogs_sbi_subscription_t *subscription = NULL;
    ogs_assert(session);
    ogs_assert(message);

    subscription = ogs_sbi_subscription_find(message->h.resource.id);
    if (subscription) {
        ogs_sbi_response_t *response = NULL;
        ogs_sbi_subscription_remove(subscription);

        response = ogs_sbi_build_response(message);
        ogs_assert(response);
        ogs_sbi_server_send_response(session, response,
            OGS_SBI_HTTP_STATUS_NO_CONTENT);
    } else {
        ogs_error("Not found [%s]", message->h.resource.id);
        ogs_sbi_server_send_error(session,
                OGS_SBI_HTTP_STATUS_NOT_FOUND,
                message, "Not found", message->h.resource.id);
    }

    return true;
}

bool nrf_nnrf_handle_nf_list_retrieval(ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    int i = 0;

    ogs_sbi_links_t *links = NULL;
    OpenAPI_lnode_t *node = NULL;

    ogs_assert(session);
    ogs_assert(recvmsg);

    links = ogs_calloc(1, sizeof(*links));
    ogs_assert(links);

    links->items = OpenAPI_list_create();
    ogs_assert(links->items);

    links->self = ogs_sbi_server_uri(server,
            recvmsg->h.service.name, recvmsg->h.api.version,
            recvmsg->h.resource.name, NULL);

    i = 0;
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {

        if (recvmsg->param.nf_type &&
                recvmsg->param.nf_type != nf_instance->nf_type)
            continue;

        if (!recvmsg->param.limit ||
             (recvmsg->param.limit && i < recvmsg->param.limit)) {
            OpenAPI_list_add(links->items,
                ogs_msprintf("%s/%s", links->self, nf_instance->id));
        }

        i++;
    }

    ogs_assert(links->self);

    memset(&sendmsg, 0, sizeof(sendmsg));
    sendmsg.links = links;
    sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;

    response = ogs_sbi_build_response(&sendmsg);
    ogs_assert(response);
    ogs_sbi_server_send_response(session, response, OGS_SBI_HTTP_STATUS_OK);

    OpenAPI_list_for_each(links->items, node) {
        if (!node->data) continue;
        ogs_free(node->data);
    }
    OpenAPI_list_free(links->items);
    ogs_free(links->self);
    ogs_free(links);

    return true;
}

bool nrf_nnrf_handle_nf_profile_retrieval(ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    OpenAPI_nf_profile_t *NFProfile = NULL;

    ogs_assert(session);
    ogs_assert(recvmsg);

    ogs_assert(recvmsg->h.resource.id);
    nf_instance = ogs_sbi_nf_instance_find(recvmsg->h.resource.id);
    if (!nf_instance) {
        ogs_error("Not found [%s]", recvmsg->h.resource.id);
        ogs_sbi_server_send_error(session,
                OGS_SBI_HTTP_STATUS_NOT_FOUND,
                recvmsg, "Not found", recvmsg->h.resource.id);
        return false;
    }

    NFProfile = ogs_sbi_nnrf_build_nf_profile(nf_instance);
    ogs_assert(NFProfile);

    memset(&sendmsg, 0, sizeof(sendmsg));
    sendmsg.NFProfile = NFProfile;

    response = ogs_sbi_build_response(&sendmsg);
    ogs_assert(response);
    ogs_sbi_server_send_response(session, response, OGS_SBI_HTTP_STATUS_OK);

    ogs_sbi_nnrf_free_nf_profile(NFProfile);

    return true;
}

bool nrf_nnrf_handle_nf_discover(ogs_sbi_server_t *server,
        ogs_sbi_session_t *session, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    OpenAPI_search_result_t *SearchResult = NULL;
    OpenAPI_lnode_t *node = NULL;
    int i;

    ogs_assert(session);
    ogs_assert(recvmsg);

    if (!recvmsg->param.target_nf_type) {
        ogs_error("No target-nf-type [%s]", recvmsg->h.url);
        ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No target-nf-type", NULL);
        return false;
    }
    if (!recvmsg->param.requester_nf_type) {
        ogs_error("No requester-nf-type [%s]", recvmsg->h.url);
        ogs_sbi_server_send_error(session, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No requester-nf-type", NULL);
        return false;
    }

    SearchResult = ogs_calloc(1, sizeof(*SearchResult));
    ogs_assert(SearchResult);

    SearchResult->validity_period = ogs_config()->time.nf_instance.validity;
    ogs_assert(SearchResult->validity_period);

    SearchResult->nf_instances = OpenAPI_list_create();
    ogs_assert(SearchResult->nf_instances);

    i = 0;
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
        OpenAPI_nf_profile_t *NFProfile = NULL;

        if (nf_instance->nf_type != recvmsg->param.target_nf_type)
            continue;
        if (nf_instance->nf_type == recvmsg->param.requester_nf_type)
            continue;

        if (!recvmsg->param.limit ||
             (recvmsg->param.limit && i < recvmsg->param.limit)) {
            NFProfile = ogs_sbi_nnrf_build_nf_profile(nf_instance);
            ogs_assert(NFProfile);

            OpenAPI_list_add(SearchResult->nf_instances, NFProfile);
        }

        i++;
    }

    if (recvmsg->param.limit) SearchResult->num_nf_inst_complete = i;

    memset(&sendmsg, 0, sizeof(sendmsg));
    sendmsg.SearchResult = SearchResult;
    sendmsg.http.cache_control =
        ogs_msprintf("max-age=%d", SearchResult->validity_period);

    response = ogs_sbi_build_response(&sendmsg);
    ogs_assert(response);
    ogs_sbi_server_send_response(session, response, OGS_SBI_HTTP_STATUS_OK);

    OpenAPI_list_for_each(SearchResult->nf_instances, node) {
        OpenAPI_nf_profile_t *NFProfile = NULL;
        if (!node->data) continue;
        NFProfile = node->data;
        ogs_sbi_nnrf_free_nf_profile(NFProfile);
    }
    OpenAPI_list_free(SearchResult->nf_instances);

    if (sendmsg.http.cache_control)
        ogs_free(sendmsg.http.cache_control);
    ogs_free(SearchResult);

    return true;
}
