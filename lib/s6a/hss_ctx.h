#ifndef __S6A_HSS_CTX_H__
#define __S6A_HSS_CTX_H__

#include "core_list.h"
#include "core_errno.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SIZE_OF_UE_POOL             128

#define MAX_IMSI_LEN                15
#define MAX_KEY_LEN                 16
#define MAX_AMF_LEN                 2

typedef struct _ue_ctx_t {
    lnode_t         node; /**< A node of list_t */

    c_uint8_t imsi[MAX_IMSI_LEN+1];
    c_uint8_t imsi_len;

    c_uint8_t k[MAX_KEY_LEN];
    c_uint8_t op[MAX_KEY_LEN];
    c_uint8_t opc[MAX_KEY_LEN];
    c_uint8_t amf[MAX_AMF_LEN];
} ue_ctx_t;

CORE_DECLARE(status_t)  hss_ctx_init(void);
CORE_DECLARE(void)      hss_ctx_final(void);

CORE_DECLARE(ue_ctx_t*) hss_ue_ctx_add(void);
CORE_DECLARE(status_t)  hss_ue_ctx_remove(ue_ctx_t *ue);
CORE_DECLARE(status_t)  hss_ue_ctx_remove_all(void);
CORE_DECLARE(ue_ctx_t*) hss_ue_ctx_find_by_imsi(c_uint8_t *imsi);
CORE_DECLARE(ue_ctx_t*) hss_ue_ctx_first(void);
CORE_DECLARE(ue_ctx_t*) hss_ue_ctx_next(ue_ctx_t *ue);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !__S6A_HSS_CTX_H__ */
