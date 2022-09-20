#include <kdw_rsa_ta.h>
#include <stored_key.h>
#include <string.h>
#include <stdlib.h>

/*
 * Currently this only supports a single key, in the future this could be
 * updated to support multiple users, all with different unique keys (stored
 * using secure storage).
 */
 
/* Generate RSA1024 key */
static TEE_OperationHandle generate_1024key()
{
	TEE_ObjectInfo info;
	rsa_key_st rsakey;

	TEE_OperationHandle keypair = TEE_HANDLE_NULL;

	memset(&rsakey, 0, sizeof(rsakey));

	TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 1024, &keypair);

	TEE_GenerateKey(keypair, 1024, NULL, 0);

	TEE_GetObjectInfo(keypair, &info);

	/* Set expected size */
	rsakey.pub_n_size = 128;
	rsakey.pub_e_size = 3;
	rsakey.prv_d_size = 128;
	rsakey.prv_p_size = 64;
	rsakey.prv_q_size = 64;
	rsakey.prv_dp_size = 64;
	rsakey.prv_dq_size = 64;
	rsakey.prv_qp_size = 64;

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_MODULUS,
				     rsakey.pub_n, &rsakey.pub_n_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     rsakey.pub_e, &rsakey.pub_e_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PRIVATE_EXPONENT,
                                     rsakey.prv_d, &rsakey.prv_d_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PRIME1,
                                     rsakey.prv_p, &rsakey.prv_p_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PRIME2,
                                     rsakey.prv_q, &rsakey.prv_q_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_EXPONENT1,
                                     rsakey.prv_dp, &rsakey.prv_dp_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_EXPONENT2,
                                     rsakey.prv_dq, &rsakey.prv_dq_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_COEFFICIENT,
                                     rsakey.prv_qp, &rsakey.prv_qp_size);

	return keypair;
}

/* Generate RSA1024 signature */
static TEE_Result rsa1024(TEE_ObjectHandle keypair, uint8_t* digest_seed)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle oh_sign = TEE_HANDLE_NULL;
	TEE_OperationHandle oh_verify = TEE_HANDLE_NULL;
	TEE_Time t1, t2, t3, t4;
	uint32_t c_sec, v_sec, c_millisec, v_millisec;
	uint64_t c_microsec, v_microsec;

	uint8_t digest[32] = { 0 };
	uint32_t digestlen;
	uint8_t rsa[128];
	uint32_t rsalen;

	TEE_MemMove(digest, digest_seed, sizeof(digest_seed) + 1);
	digestlen = 32;
	rsalen = 128;

	res = TEE_AllocateOperation(&oh_sign, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
                              	    TEE_MODE_SIGN, 1024);

        res = TEE_SetOperationKey(oh_sign, keypair);

	TEE_GetSystemTime(&t1);
	
	res = TEE_AsymmetricSignDigest(oh_sign, (TEE_Attribute *)NULL, 0,
			               digest, digestlen, rsa, &rsalen);
				       
	TEE_GetSystemTime(&t2);

	c_sec = t2.seconds - t1.seconds;
	c_millisec = t2.millis - t1.millis;
	c_microsec = t2.micros - t1.micros;
	IMSG("Generated a signature (RSA1024) for %dbytes in %d(s) %d(ms) %d(us)\n",
	     digestlen, c_sec, c_millisec, c_microsec);

	res = TEE_AllocateOperation(&oh_verify, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
                              	    TEE_MODE_VERIFY, 1024);

        res = TEE_SetOperationKey(oh_verify, keypair);

	TEE_GetSystemTime(&t3);

        res = TEE_AsymmetricVerifyDigest(oh_verify, (TEE_Attribute *)NULL, 0,
                                         digest, digestlen, rsa, rsalen);

        TEE_GetSystemTime(&t4);

        v_sec = t4.seconds - t3.seconds;
        v_millisec = t4.millis - t3.millis;
        v_microsec = t4.micros - t3.micros;
        IMSG("Verified a signature (RSA1024) for %dbytes in %d(s) %d(ms) %d(us)\n",
             digestlen, v_sec, v_millisec, v_microsec);

	return res;
}

/* Generate RSA2048 key */
static TEE_OperationHandle generate_2048key()
{
	TEE_ObjectInfo info;
	rsa_key_st rsakey;

	TEE_ObjectHandle keypair = TEE_HANDLE_NULL;

	memset(&rsakey, 0, sizeof(rsakey));

	TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &keypair);

	TEE_GenerateKey(keypair, 2048, NULL, 0);

	TEE_GetObjectInfo(keypair, &info);

	/* Set expected size */
	rsakey.pub_n_size = 256;
	rsakey.pub_e_size = 3;
	rsakey.prv_d_size = 256;
	rsakey.prv_p_size = 128;
	rsakey.prv_q_size = 128;
	rsakey.prv_dp_size = 128;
	rsakey.prv_dq_size = 128;
	rsakey.prv_qp_size = 128;

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_MODULUS,
				     rsakey.pub_n, &rsakey.pub_n_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PUBLIC_EXPONENT,
				     rsakey.pub_e, &rsakey.pub_e_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PRIVATE_EXPONENT,
                                     rsakey.prv_d, &rsakey.prv_d_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PRIME1,
                                     rsakey.prv_p, &rsakey.prv_p_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_PRIME2,
                                     rsakey.prv_q, &rsakey.prv_q_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_EXPONENT1,
                                     rsakey.prv_dp, &rsakey.prv_dp_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_EXPONENT2,
                                     rsakey.prv_dq, &rsakey.prv_dq_size);

	TEE_GetObjectBufferAttribute(keypair, TEE_ATTR_RSA_COEFFICIENT,
                                     rsakey.prv_qp, &rsakey.prv_qp_size);

	return keypair;
}

/* Generate RSA2048 signature */
static TEE_Result rsa2048(TEE_ObjectHandle keypair, uint8_t* digest_seed)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle oh_sign = TEE_HANDLE_NULL;
	TEE_OperationHandle oh_verify = TEE_HANDLE_NULL;
	TEE_Time t1, t2, t3, t4;
	uint32_t c_sec, c_millisec, v_sec, v_millisec;
	uint64_t c_microsec, v_microsec;

	uint8_t digest[32] = { 0 };
	uint32_t digestlen;
	uint8_t rsa[256];
	uint32_t rsalen;

	TEE_MemMove(digest, digest_seed, sizeof(digest_seed) + 1);
	digestlen = 32;
	rsalen = 256;

	res = TEE_AllocateOperation(&oh_sign, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
				    TEE_MODE_SIGN, 2048);

	res = TEE_SetOperationKey(oh_sign, keypair);

	TEE_GetSystemTime(&t1);
	
	TEE_AsymmetricSignDigest(oh_sign, (TEE_Attribute *)NULL, 0,
			         digest, digestlen, rsa, &rsalen);
				       
	TEE_GetSystemTime(&t2);

	c_sec = t2.seconds - t1.seconds;
	c_millisec = t2.millis - t1.millis;
	c_microsec = t2.micros - t1.micros;
	IMSG("Generated a signature (RSA2048) for %dbytes in %d(s) %d(ms) %d(us)\n",
	     digestlen, c_sec, c_millisec, c_microsec);

	res = TEE_AllocateOperation(&oh_verify, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
                              	    TEE_MODE_VERIFY, 2048);

        res = TEE_SetOperationKey(oh_verify, keypair);

        TEE_GetSystemTime(&t3);

        res = TEE_AsymmetricVerifyDigest(oh_verify, (TEE_Attribute *)NULL, 0,
                                         digest, digestlen, rsa, rsalen);

        TEE_GetSystemTime(&t4);

        v_sec = t4.seconds - t3.seconds;
        v_millisec = t4.millis - t3.millis;
        v_microsec = t4.micros - t3.micros;
        IMSG("Verified a signature (RSA2048) for %dbytes in %d(s) %d(ms) %d(us)\n",
             digestlen, v_sec, v_millisec, v_microsec);

	return res;
}

/* Get RSA2048 value */
static TEE_Result get_rsa(uint32_t param_types, TEE_Param __maybe_unused params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle op1024 = TEE_HANDLE_NULL;
	TEE_ObjectHandle op2048 = TEE_HANDLE_NULL;
	TEE_ObjectHandle op192 = TEE_HANDLE_NULL;

	uint8_t in[32];

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
	{
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	
	memset(in, 0, params[0].memref.size);
	memcpy(in, params[0].memref.buffer, params[0].memref.size);
	
	/* RSA1024 Key Generation */
	//op1024 = generate_1024key();
	
	/* RSA1024 Implementation */
	//res = rsa1024(op1024, in);
	
	/* RSA2048 Key Generation */
	op2048 = generate_2048key();

	/* RSA2048 Implementation */
	res =  rsa2048(op2048, in);
	
        return res;
}

/***************************************************************************
 * Mandatory TA functions.
 **************************************************************************/
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("RSA Signing!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Complete!\n");
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_GET_RSA:
		return get_rsa(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
