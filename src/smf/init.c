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
#include "fd-path.h"

static ogs_thread_t *thread;
static void smf_main(void *data);

static int initialized = 0;

int smf_initialize()
{
    int rv;

    ogs_pfcp_context_init(ogs_config()->max.upf * OGS_MAX_NUM_OF_GTPU_RESOURCE);
    smf_context_init();
    smf_event_init(); /* Create event with poll, timer */
    ogs_sbi_context_init(smf_self()->pollset, smf_self()->timer_mgr); 

    rv = ogs_gtp_xact_init(smf_self()->timer_mgr, 512);
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_xact_init(smf_self()->timer_mgr, 512);
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_context_parse_config("smf", "upf");
    if (rv != OGS_OK) return rv;

    rv = ogs_sbi_context_parse_config("smf", "nrf");
    if (rv != OGS_OK) return rv;

    rv = smf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_config()->logger.domain, ogs_config()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_ue_pool_generate();
    if (rv != OGS_OK) return rv;

    rv = smf_fd_init();
    if (rv != 0) return OGS_ERROR;

    thread = ogs_thread_create(smf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* Sending NF Instance De-registeration to NRF */
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance)
        smf_nf_fsm_fini(nf_instance);

    /* Starting holding timer */
    t_termination_holding = ogs_timer_add(smf_self()->timer_mgr, NULL, NULL);
    ogs_assert(t_termination_holding);
#define TERMINATION_HOLDING_TIME ogs_time_from_msec(300)
    ogs_timer_start(t_termination_holding, TERMINATION_HOLDING_TIME);

    /* Sending termination event to the queue */
    ogs_queue_term(smf_self()->queue);
    ogs_pollset_notify(smf_self()->pollset);
}

void smf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    smf_fd_final();

    smf_context_final();
    ogs_pfcp_context_final();
    ogs_sbi_context_final();

    ogs_pfcp_xact_final();
    ogs_gtp_xact_final();

    smf_event_final(); /* Destroy event */
}

static void smf_main(void *data)
{
    ogs_fsm_t smf_sm;
    int rv;

    ogs_fsm_create(&smf_sm, smf_state_initial, smf_state_final);
    ogs_fsm_init(&smf_sm, 0);

    for ( ;; ) {
        ogs_pollset_poll(smf_self()->pollset,
                ogs_timer_mgr_next(smf_self()->timer_mgr));

        /*
         * After ogs_pollset_poll(), ogs_timer_mgr_expire() must be called.
         *
         * The reason is why ogs_timer_mgr_next() can get the corrent value
         * when ogs_timer_stop() is called internally in ogs_timer_mgr_expire().
         *
         * You should not use event-queue before ogs_timer_mgr_expire().
         * In this case, ogs_timer_mgr_expire() does not work
         * because 'if rv == OGS_DONE' statement is exiting and
         * not calling ogs_timer_mgr_expire().
         */
        ogs_timer_mgr_expire(smf_self()->timer_mgr);

        for ( ;; ) {
            smf_event_t *e = NULL;

            rv = ogs_queue_trypop(smf_self()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&smf_sm, e);
            smf_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&smf_sm, 0);
    ogs_fsm_delete(&smf_sm);
}
