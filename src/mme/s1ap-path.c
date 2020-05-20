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

#include "ogs-sctp.h"

#include "mme-event.h"
#include "mme-timer.h"

#include "nas-security.h"
#include "nas-path.h"

#include "s1ap-build.h"
#include "s1ap-path.h"

int s1ap_open(void)
{
    ogs_socknode_t *node = NULL;

    ogs_list_for_each(&mme_self()->s1ap_list, node)
        s1ap_server(node);

    ogs_list_for_each(&mme_self()->s1ap_list6, node)
        s1ap_server(node);

    return OGS_OK;
}

void s1ap_close()
{
    ogs_socknode_remove_all(&mme_self()->s1ap_list);
    ogs_socknode_remove_all(&mme_self()->s1ap_list6);
}

int s1ap_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf,
        ogs_sockaddr_t *addr, uint16_t stream_no)
{
    int sent;

    ogs_assert(sock);
    ogs_assert(pkbuf);

    sent = ogs_sctp_sendmsg(sock, pkbuf->data, pkbuf->len,
            addr, OGS_SCTP_S1AP_PPID, stream_no);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("ogs_sctp_sendmsg error (%d:%s)", errno, strerror(errno));
        return OGS_ERROR;
    }
    ogs_pkbuf_free(pkbuf);

    return OGS_OK;
}

int s1ap_send_to_enb(mme_enb_t *enb, ogs_pkbuf_t *pkbuf, uint16_t stream_no)
{
    char buf[OGS_ADDRSTRLEN];
    int rv;

    ogs_assert(enb);
    ogs_assert(pkbuf);
    ogs_assert(enb->sock);

    ogs_debug("    IP[%s] ENB_ID[%d]",
            OGS_ADDR(enb->addr, buf), enb->enb_id);

    rv = s1ap_send(enb->sock, pkbuf,
            enb->sock_type == SOCK_STREAM ? NULL : enb->addr,
            stream_no);
    if (rv != OGS_OK) {
        ogs_error("s1ap_send() failed");

        ogs_pkbuf_free(pkbuf);
        s1ap_event_push(MME_EVT_S1AP_LO_CONNREFUSED,
                enb->sock, enb->addr, NULL, 0, 0);
    }

    return rv;
}

int s1ap_send_to_enb_ue(enb_ue_t *enb_ue, ogs_pkbuf_t *pkbuf)
{
    mme_enb_t *enb = NULL;

    ogs_assert(enb_ue);
    enb = enb_ue->enb;
    ogs_assert(enb);

    return s1ap_send_to_enb(enb, pkbuf, enb_ue->enb_ostream_id);
}

int s1ap_delayed_send_to_enb_ue(
        enb_ue_t *enb_ue, ogs_pkbuf_t *pkbuf, ogs_time_t duration)
{
    ogs_assert(enb_ue);
    ogs_assert(pkbuf);
        
    if (duration) {
        mme_event_t *e = NULL;

        e = mme_event_new(MME_EVT_S1AP_TIMER);
        ogs_assert(e);
        e->timer = ogs_timer_add(
                mme_self()->timer_mgr, mme_timer_s1_delayed_send, e);
        ogs_assert(e->timer);
        e->pkbuf = pkbuf;
        e->enb_ue = enb_ue;
        e->enb = enb_ue->enb;

        ogs_timer_start(e->timer, duration);

        return OGS_OK;
    } else {
        mme_enb_t *enb = NULL;
        enb = enb_ue->enb;
        ogs_assert(enb);
        return s1ap_send_to_enb_ue(enb_ue, pkbuf);
    }
}

int s1ap_send_to_esm(mme_ue_t *mme_ue, ogs_pkbuf_t *esmbuf)
{
    int rv;
    mme_event_t *e = NULL;

    ogs_assert(mme_ue);
    ogs_assert(esmbuf);

    e = mme_event_new(MME_EVT_ESM_MESSAGE);
    ogs_assert(e);
    e->mme_ue = mme_ue;
    e->pkbuf = esmbuf;
    rv = ogs_queue_push(mme_self()->queue, e);
    if (rv != OGS_OK) {
        ogs_warn("ogs_queue_push() failed:%d", (int)rv);
        ogs_pkbuf_free(e->pkbuf);
        mme_event_free(e);
    }

    return rv;
}
 
int s1ap_send_to_nas(enb_ue_t *enb_ue,
        S1AP_ProcedureCode_t procedureCode, S1AP_NAS_PDU_t *nasPdu)
{
    ogs_nas_security_header_t *sh = NULL;
    nas_security_header_type_t security_header_type;

    ogs_nas_emm_header_t *h = NULL;
    ogs_pkbuf_t *nasbuf = NULL;
    mme_event_t *e = NULL;

    ogs_assert(enb_ue);
    ogs_assert(nasPdu);

    /* The Packet Buffer(pkbuf_t) for NAS message MUST make a HEADROOM. 
     * When calculating AES_CMAC, we need to use the headroom of the packet. */
    nasbuf = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM+nasPdu->size);
    ogs_pkbuf_reserve(nasbuf, OGS_NAS_HEADROOM);
    ogs_pkbuf_put_data(nasbuf, nasPdu->buf, nasPdu->size);

    sh = (ogs_nas_security_header_t *)nasbuf->data;
    ogs_assert(sh);

    memset(&security_header_type, 0, sizeof(nas_security_header_type_t));
    switch(sh->security_header_type) {
    case OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE:
        break;
    case OGS_NAS_SECURITY_HEADER_FOR_SERVICE_REQUEST_MESSAGE:
        security_header_type.service_request = 1;
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED:
        security_header_type.integrity_protected = 1;
        ogs_pkbuf_pull(nasbuf, 6);
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED:
        security_header_type.integrity_protected = 1;
        security_header_type.ciphered = 1;
        ogs_pkbuf_pull(nasbuf, 6);
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
        security_header_type.integrity_protected = 1;
        security_header_type.new_security_context = 1;
        ogs_pkbuf_pull(nasbuf, 6);
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT:
        security_header_type.integrity_protected = 1;
        security_header_type.ciphered = 1;
        security_header_type.new_security_context = 1;
        ogs_pkbuf_pull(nasbuf, 6);
        break;
    default:
        ogs_error("Not implemented(security header type:0x%x)",
                sh->security_header_type);
        return OGS_ERROR;
    }

    if (enb_ue->mme_ue) {
        if (nas_security_decode(enb_ue->mme_ue,
                security_header_type, nasbuf) != OGS_OK) {
            ogs_error("nas_security_decode failed()");
	        return OGS_ERROR;
        }
    }

    h = (ogs_nas_emm_header_t *)nasbuf->data;
    ogs_assert(h);
    if (h->protocol_discriminator == OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM) {
        int rv;
        e = mme_event_new(MME_EVT_EMM_MESSAGE);
        ogs_assert(e);
        e->enb_ue = enb_ue;
        e->s1ap_code = procedureCode;
        e->nas_type = security_header_type.type;
        e->pkbuf = nasbuf;
        rv = ogs_queue_push(mme_self()->queue, e);
        if (rv != OGS_OK) {
            ogs_warn("ogs_queue_push() failed:%d", (int)rv);
            ogs_pkbuf_free(e->pkbuf);
            mme_event_free(e);
        }
        return rv;
    } else if (h->protocol_discriminator == OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM) {
        mme_ue_t *mme_ue = enb_ue->mme_ue;
        ogs_assert(mme_ue);
        return s1ap_send_to_esm(mme_ue, nasbuf);
    } else {
        ogs_error("Unknown/Unimplemented NAS Protocol discriminator 0x%02x",
                  h->protocol_discriminator);
        return OGS_ERROR;
    }
}

void s1ap_send_s1_setup_response(mme_enb_t *enb)
{
    ogs_pkbuf_t *s1ap_buffer;

    ogs_debug("[MME] S1-Setup response");
    s1ap_buffer = s1ap_build_setup_rsp();
    ogs_expect_or_return(s1ap_buffer);

    ogs_expect(OGS_OK ==
            s1ap_send_to_enb(enb, s1ap_buffer, S1AP_NON_UE_SIGNALLING));
}

void s1ap_send_s1_setup_failure(
        mme_enb_t *enb, S1AP_Cause_PR group, long cause)
{
    ogs_pkbuf_t *s1ap_buffer;

    ogs_debug("[MME] S1-Setup failure");
    s1ap_buffer = s1ap_build_setup_failure(group, cause, S1AP_TimeToWait_v10s);
    ogs_expect_or_return(s1ap_buffer);

    ogs_expect(OGS_OK ==
            s1ap_send_to_enb(enb, s1ap_buffer, S1AP_NON_UE_SIGNALLING));
}

void s1ap_send_initial_context_setup_request(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(mme_ue);

    s1apbuf = s1ap_build_initial_context_setup_request(mme_ue, NULL);
    ogs_expect_or_return(s1apbuf);

    rv = nas_send_to_enb(mme_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_ue_context_modification_request(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(mme_ue);

    s1apbuf = s1ap_build_ue_context_modification_request(mme_ue);
    ogs_expect_or_return(s1apbuf);

    rv = nas_send_to_enb(mme_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_ue_context_release_command(
    enb_ue_t *enb_ue, S1AP_Cause_PR group, long cause,
    uint8_t action, uint32_t delay)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(enb_ue);

    ogs_debug("[MME] UE Context release command");
    ogs_debug("    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);

    if (delay) {
        ogs_assert(action != S1AP_UE_CTX_REL_INVALID_ACTION);
        enb_ue->ue_ctx_rel_action = action;

        ogs_debug("    Group[%d] Cause[%d] Action[%d] Delay[%d]",
                group, (int)cause, action, delay);

        s1apbuf = s1ap_build_ue_context_release_command(enb_ue, group, cause);
        ogs_expect_or_return(s1apbuf);

        rv = s1ap_delayed_send_to_enb_ue(enb_ue, s1apbuf, delay);
        ogs_expect(rv == OGS_OK);
    } else {
        ogs_assert(action != S1AP_UE_CTX_REL_INVALID_ACTION);
        enb_ue->ue_ctx_rel_action = action;

        ogs_debug("    Group[%d] Cause[%d] Action[%d] Delay[%d]",
                group, (int)cause, action, delay);

        s1apbuf = s1ap_build_ue_context_release_command(enb_ue, group, cause);
        ogs_expect_or_return(s1apbuf);

        rv = s1ap_delayed_send_to_enb_ue(enb_ue, s1apbuf, 0);
        ogs_expect(rv == OGS_OK);
    }
}

void s1ap_send_paging(mme_ue_t *mme_ue, S1AP_CNDomain_t cn_domain)
{
    ogs_pkbuf_t *s1apbuf = NULL;
    mme_enb_t *enb = NULL;
    int i;
    int rv;

    /* Find enB with matched TAI */
    ogs_list_for_each(&mme_self()->enb_list, enb) {
        for (i = 0; i < enb->num_of_supported_ta_list; i++) {

            if (memcmp(&enb->supported_ta_list[i], &mme_ue->tai,
                        sizeof(ogs_tai_t)) == 0) {

                if (mme_ue->t3413.pkbuf) {
                    s1apbuf = mme_ue->t3413.pkbuf;
                } else {
                    s1apbuf = s1ap_build_paging(mme_ue, cn_domain);
                    ogs_expect_or_return(s1apbuf);
                }

                mme_ue->t3413.pkbuf = ogs_pkbuf_copy(s1apbuf);

                rv = s1ap_send_to_enb(enb, s1apbuf, S1AP_NON_UE_SIGNALLING);
                ogs_expect(rv == OGS_OK);
            }
        }
    }

    /* Start T3413 */
    ogs_timer_start(mme_ue->t3413.timer, 
            mme_timer_cfg(MME_TIMER_T3413)->duration);
}

void s1ap_send_mme_configuration_transfer(
        mme_enb_t *target_enb,
        S1AP_SONConfigurationTransfer_t *SONConfigurationTransfer)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(target_enb);
    ogs_assert(SONConfigurationTransfer);

    s1apbuf = s1ap_build_mme_configuration_transfer(SONConfigurationTransfer);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb(target_enb, s1apbuf, S1AP_NON_UE_SIGNALLING);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_path_switch_ack(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(mme_ue);

    s1apbuf = s1ap_build_path_switch_ack(mme_ue);
    ogs_expect_or_return(s1apbuf);

    rv = nas_send_to_enb(mme_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_handover_command(enb_ue_t *source_ue)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(source_ue);

    s1apbuf = s1ap_build_handover_command(source_ue);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb_ue(source_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_handover_preparation_failure(
        enb_ue_t *source_ue, S1AP_Cause_t *cause)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(source_ue);
    ogs_assert(cause);

    s1apbuf = s1ap_build_handover_preparation_failure(source_ue, cause);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb_ue(source_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_handover_cancel_ack(enb_ue_t *source_ue)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(source_ue);

    s1apbuf = s1ap_build_handover_cancel_ack(source_ue);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb_ue(source_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}


void s1ap_send_handover_request(
        mme_ue_t *mme_ue,
        mme_enb_t *target_enb,
        S1AP_ENB_UE_S1AP_ID_t *enb_ue_s1ap_id,
        S1AP_MME_UE_S1AP_ID_t *mme_ue_s1ap_id,
        S1AP_HandoverType_t *handovertype,
        S1AP_Cause_t *cause,
        S1AP_Source_ToTarget_TransparentContainer_t
            *source_totarget_transparentContainer)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    enb_ue_t *source_ue = NULL, *target_ue = NULL;

    ogs_debug("[MME] Handover request");
    
    ogs_assert(target_enb);

    ogs_assert(mme_ue);
    source_ue = mme_ue->enb_ue;
    ogs_assert(source_ue);
    ogs_assert(source_ue->target_ue == NULL);

    target_ue = enb_ue_add(target_enb, INVALID_UE_S1AP_ID);
    ogs_assert(target_ue);

    ogs_debug("    Source : ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
            source_ue->enb_ue_s1ap_id, source_ue->mme_ue_s1ap_id);
    ogs_debug("    Target : ENB_UE_S1AP_ID[Unknown] MME_UE_S1AP_ID[%d]",
            target_ue->mme_ue_s1ap_id);

    source_ue_associate_target_ue(source_ue, target_ue);

    s1apbuf = s1ap_build_handover_request(mme_ue, target_ue,
            enb_ue_s1ap_id, mme_ue_s1ap_id,
            handovertype, cause,
            source_totarget_transparentContainer);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb_ue(target_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_mme_status_transfer(
        enb_ue_t *target_ue,
        S1AP_ENB_StatusTransfer_TransparentContainer_t
            *enb_statustransfer_transparentContainer)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(target_ue);

    s1apbuf = s1ap_build_mme_status_transfer(target_ue,
            enb_statustransfer_transparentContainer);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb_ue(target_ue, s1apbuf);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_error_indication(
        mme_enb_t *enb,
        S1AP_MME_UE_S1AP_ID_t *mme_ue_s1ap_id,
        S1AP_ENB_UE_S1AP_ID_t *enb_ue_s1ap_id,
        S1AP_Cause_PR group, long cause)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(enb);

    s1apbuf = s1ap_build_error_indication(
            mme_ue_s1ap_id, enb_ue_s1ap_id, group, cause);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb(enb, s1apbuf, S1AP_NON_UE_SIGNALLING);
    ogs_expect(rv == OGS_OK);
}

void s1ap_send_s1_reset_ack(
        mme_enb_t *enb,
        S1AP_UE_associatedLogicalS1_ConnectionListRes_t *partOfS1_Interface)
{
    int rv;
    ogs_pkbuf_t *s1apbuf = NULL;

    ogs_assert(enb);

    s1apbuf = s1ap_build_s1_reset_ack(partOfS1_Interface);
    ogs_expect_or_return(s1apbuf);

    rv = s1ap_send_to_enb(enb, s1apbuf, S1AP_NON_UE_SIGNALLING);
    ogs_expect(rv == OGS_OK);
}
