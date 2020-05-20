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

#include "sbi-path.h"
#include "nnrf-handler.h"

void nrf_nf_fsm_init(ogs_sbi_nf_instance_t *nf_instance)
{
    nrf_event_t e;

    ogs_assert(nf_instance);
    e.nf_instance = nf_instance;

    ogs_fsm_create(&nf_instance->sm,
            nrf_nf_state_initial, nrf_nf_state_final);
    ogs_fsm_init(&nf_instance->sm, &e);
}

void nrf_nf_fsm_fini(ogs_sbi_nf_instance_t *nf_instance)
{
    nrf_event_t e;

    ogs_assert(nf_instance);
    e.nf_instance = nf_instance;

    ogs_fsm_fini(&nf_instance->sm, &e);
    ogs_fsm_delete(&nf_instance->sm);
}

void nrf_nf_state_initial(ogs_fsm_t *s, nrf_event_t *e)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_assert(s);
    ogs_assert(e);

    nrf_sm_debug(e);

    nf_instance = e->nf_instance;
    ogs_assert(nf_instance);

    nf_instance->t_heartbeat = ogs_timer_add(nrf_self()->timer_mgr,
            nrf_timer_nf_instance_heartbeat, nf_instance);
    ogs_assert(nf_instance->t_heartbeat);

    OGS_FSM_TRAN(s, &nrf_nf_state_will_register);
}

void nrf_nf_state_final(ogs_fsm_t *s, nrf_event_t *e)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_assert(s);
    ogs_assert(e);

    nrf_sm_debug(e);

    nf_instance = e->nf_instance;
    ogs_assert(nf_instance);

    ogs_timer_delete(nf_instance->t_heartbeat);
}

void nrf_nf_state_will_register(ogs_fsm_t *s, nrf_event_t *e)
{
    bool handled;
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_session_t *session = NULL;
    ogs_sbi_message_t *message = NULL;

    ogs_assert(s);
    ogs_assert(e);

    nrf_sm_debug(e);

    nf_instance = e->nf_instance;
    ogs_assert(nf_instance);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    case NRF_EVT_SBI_SERVER:
        message = e->sbi.message;
        ogs_assert(message);
        session = e->sbi.session;
        ogs_assert(session);
        server = e->sbi.server;
        ogs_assert(server);

        SWITCH(message->h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NRF_NFM)

            SWITCH(message->h.resource.name)
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)

                SWITCH(message->h.method)
                CASE(OGS_SBI_HTTP_METHOD_PUT)

                    handled = nrf_nnrf_handle_nf_register(
                            nf_instance, server, session, message);
                    if (handled == false)
                        OGS_FSM_TRAN(s, nrf_nf_state_exception);
                    break;

                DEFAULT
                    ogs_error("Invalid HTTP method [%s]",
                            message->h.method);
                    ogs_sbi_server_send_error(session,
                            OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, message,
                            "Invalid HTTP method", message->h.method);
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message->h.resource.name);
                ogs_sbi_server_send_error(session,
                        OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, message,
                        "Invalid resource name", message->h.resource.name);
            END
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message->h.service.name);
            ogs_sbi_server_send_error(session,
                    OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, message,
                    "Invalid resource name", message->h.service.name);
        END

        OGS_FSM_TRAN(s, nrf_nf_state_registered);
        break;

    default:
        ogs_error("Unknown event %s", nrf_event_get_name(e));
        ogs_sbi_server_send_error(session,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                message, "Unknown event", nrf_event_get_name(e));
        OGS_FSM_TRAN(s, nrf_nf_state_exception);
        break;
    }
}

void nrf_nf_state_registered(ogs_fsm_t *s, nrf_event_t *e)
{
    bool handled;
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_session_t *session = NULL;
    ogs_sbi_message_t *message = NULL;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(s);
    ogs_assert(e);

    nrf_sm_debug(e);

    nf_instance = e->nf_instance;
    ogs_assert(nf_instance);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        ogs_info("NF registred [%s]", nf_instance->id);
        if (nf_instance->time.heartbeat) {
            ogs_timer_start(nf_instance->t_heartbeat,
                ogs_time_from_sec(nf_instance->time.heartbeat) *
                    OGS_SBI_HEARTBEAT_RETRYCOUNT);
        }

        nrf_sbi_send_nf_status_notify_all(
                OpenAPI_notification_event_type_NF_REGISTERED, nf_instance);
        break;

    case OGS_FSM_EXIT_SIG:
        ogs_info("NF de-registered [%s]", nf_instance->id);
        if (nf_instance->time.heartbeat) {
            ogs_timer_stop(nf_instance->t_heartbeat);
        }

        nrf_sbi_send_nf_status_notify_all(
                OpenAPI_notification_event_type_NF_DEREGISTERED, nf_instance);
        break;

    case NRF_EVT_SBI_SERVER:
        message = e->sbi.message;
        ogs_assert(message);
        session = e->sbi.session;
        ogs_assert(session);
        server = e->sbi.server;
        ogs_assert(server);

        SWITCH(message->h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NRF_NFM)

            SWITCH(message->h.resource.name)
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)

                SWITCH(message->h.method)
                CASE(OGS_SBI_HTTP_METHOD_PUT)
                CASE(OGS_SBI_HTTP_METHOD_PATCH)
                    if (nf_instance->time.heartbeat) {
                        ogs_timer_start(nf_instance->t_heartbeat,
                            ogs_time_from_sec(nf_instance->time.heartbeat) *
                                OGS_SBI_HEARTBEAT_RETRYCOUNT);
                    }

                    handled = nrf_nnrf_handle_nf_update(
                            nf_instance, server, session, message);
                    if (handled == false)
                        OGS_FSM_TRAN(s, nrf_nf_state_exception);
                    break;

                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                    response = ogs_sbi_build_response(message);
                    ogs_assert(response);
                    ogs_sbi_server_send_response(session, response,
                        OGS_SBI_HTTP_STATUS_NO_CONTENT);
                    OGS_FSM_TRAN(s, nrf_nf_state_de_registered);
                    break;

                DEFAULT
                    ogs_error("Invalid HTTP method [%s]",
                            message->h.method);
                    ogs_sbi_server_send_error(session,
                            OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, message,
                            "Invalid HTTP method", message->h.method);
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message->h.resource.name);
                ogs_sbi_server_send_error(session,
                        OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, message,
                        "Invalid resource name", message->h.resource.name);
            END
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message->h.service.name);
            ogs_sbi_server_send_error(session,
                    OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, message,
                    "Invalid resource name", message->h.service.name);
        END
        break;

    default:
        ogs_error("Unknown event %s", nrf_event_get_name(e));
        ogs_sbi_server_send_error(session,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                message, "Unknown event", nrf_event_get_name(e));
        OGS_FSM_TRAN(s, nrf_nf_state_exception);
        break;
    }
}

void nrf_nf_state_de_registered(ogs_fsm_t *s, nrf_event_t *e)
{
    ogs_assert(s);
    ogs_assert(e);

    nrf_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", nrf_event_get_name(e));
        break;
    }
}

void nrf_nf_state_exception(ogs_fsm_t *s, nrf_event_t *e)
{
    ogs_assert(s);
    ogs_assert(e);

    nrf_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", nrf_event_get_name(e));
        break;
    }
}
