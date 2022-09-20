#ifndef __STORED_KEY_H__
#define __STORED_KEY_H__

#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <stdint.h>

typedef struct _rsa_key_st {
	uint8_t pub_n[256];
	uint8_t pub_e[3]; /* 65537 as default value */
	uint8_t prv_d[256];
	uint8_t prv_p[128];
	uint8_t prv_q[128];
	uint8_t prv_dp[128];
	uint8_t prv_dq[128];
	uint8_t prv_qp[128];
	uint32_t pub_n_size;
	uint32_t pub_e_size;
	uint32_t prv_d_size;
	uint32_t prv_p_size;
	uint32_t prv_q_size;
	uint32_t prv_dp_size;
	uint32_t prv_dq_size;
	uint32_t prv_qp_size;
} rsa_key_st;

typedef struct _ecdsa_key_st {
	uint8_t pub_x[512];
	uint8_t pub_y[512];
	uint8_t prv_d[512];
	uint32_t pub_x_size;
	uint32_t pub_y_size;
	uint32_t prv_d_size;
	uint32_t curve_type;
} ecdsa_key_st;

#endif /* __STORED_KEY_H__ */
