#include <kdw_mac_ta.h>
#include <string.h>
#include <stdlib.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

#define SHA1_HASH_SIZE 20 /* In bytes */
#define SHA224_HASH_SIZE 28 /* In bytes */
#define SHA256_HASH_SIZE 64 /* In bytes */
#define SHA384_HASH_SIZE 48 /* In bytes */
#define SHA512_HASH_SIZE 64 /* In bytes */
#define BUFFER_SIZE 2048 /* In bytes */

/*
 * Currently this only supports a single key, in the future this could be
 * updated to support multiple users, all with different unique keys (stored
 * using secure storage).
 */
static uint8_t K[32];
static uint32_t K_len;

/*
 * HMAC a block of memory to produce the authentication tag
 * @param key	    The secret key
 * @param keylen    The length of the secret key (bytes)
 * @param in        The data to HMAC
 * @param inlen     The length of the data to HMAC (bytes)
 * @param out       [out] Destination of the authentication tag
 * @param outlen    [in/out] Max size and resulting size of authentication tag
 */

/* HMAC-SHA1 calculation */
static TEE_Result hmac_sha1(const uint8_t* key, const uint32_t keylen,
			    const char* in, const uint32_t inlen,
			    uint8_t* out, uint32_t outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	TEE_Time t1, t2;
	uint32_t sec, millisec;
	uint64_t microsec;		

	/* Calculation procedure of HMAC-SHA1 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA1,
				    TEE_MODE_MAC, keylen * 8);

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, keylen * 8,
					  &key_handle);
	
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	
	res = TEE_SetOperationKey(op_handle, key_handle);

	TEE_MACInit(op_handle, NULL, 0);

	TEE_MACUpdate(op_handle, in, inlen);

	TEE_GetSystemTime(&t1);

	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, &outlen);
	
	TEE_GetSystemTime(&t2);

	sec = t2.seconds - t1.seconds;
	millisec = t2.millis - t1.millis;
	microsec = t2.micros - t1.micros;
	IMSG("Buffer size: %d\nTagged MAC(SHA1) in %d(s) %d(ms) %d(us)\n",
	     inlen, sec, millisec, microsec);
	     
	return res;
}

/* HMAC-SHA1 verification */
static TEE_Result verify_hmac_sha1(const uint8_t* key, const uint32_t keylen,
				   const char* in, const uint32_t inlen,
				   uint8_t* out, uint32_t outlen)
{
	TEE_Attribute attr = { 0 };
        TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
        TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
        TEE_Result res = TEE_SUCCESS;

        TEE_Time t1, t2;
        uint32_t sec, millisec;
        uint64_t microsec;                

        /* Verification procedure of HMAC-SHA1 */
        res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA1,
                                    TEE_MODE_MAC, keylen * 8);

        res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, keylen * 8,
                                          &key_handle);

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

        res = TEE_PopulateTransientObject(key_handle, &attr, 1);

        res = TEE_SetOperationKey(op_handle, key_handle);

        TEE_MACInit(op_handle, NULL, 0);

        TEE_MACUpdate(op_handle, in, inlen);

        TEE_GetSystemTime(&t1);

        res = TEE_MACCompareFinal(op_handle, NULL, 0, out, outlen);

        TEE_GetSystemTime(&t2);

        sec = t2.seconds - t1.seconds;
        millisec = t2.millis - t1.millis;
        microsec = t2.micros - t1.micros;
        IMSG("Buffer size: %d\nVerified MAC(SHA1) in %d(s) %d(ms) %d(us)\n",
             inlen, sec, millisec, microsec);

        return res;
}

/* HMAC-SHA224 calculation */
static TEE_Result hmac_sha224(const uint8_t* key, const uint32_t keylen,
			      const char* in, const uint32_t inlen,
			      uint8_t* out, uint32_t outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	TEE_Time t1, t2, t3, t4;
	uint32_t sec, millisec;
	uint64_t microsec;

	/* Calculation procedure of HMAC-SHA224 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA224,
				    TEE_MODE_MAC, keylen * 8);

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA224, keylen * 8,
					  &key_handle);
	
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	
	res = TEE_SetOperationKey(op_handle, key_handle);

	TEE_MACInit(op_handle, NULL, 0);

	TEE_MACUpdate(op_handle, in, inlen);

	TEE_GetSystemTime(&t1);

	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, &outlen);
	
	TEE_GetSystemTime(&t2);

	sec = t2.seconds - t1.seconds;
	millisec = t2.millis - t1.millis;
	microsec = t2.micros - t1.micros;
	IMSG("Buffer size: %d\nTagged MAC(SHA224) in %d(s) %d(ms) %d(us)\n",
	     inlen, sec, millisec, microsec);

	return res;
}

/* HMAC-SHA224 verification */
static TEE_Result verify_hmac_sha224(const uint8_t* key, const uint32_t keylen,
                                     const char* in, const uint32_t inlen,
                                     uint8_t* out, uint32_t outlen)
{
        TEE_Attribute attr = { 0 };
        TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
        TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
        TEE_Result res = TEE_SUCCESS;

        TEE_Time t1, t2;
        uint32_t sec, millisec;
        uint64_t microsec;

        /* Verification procedure of HMAC-SHA224 */
        res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA224,
                                    TEE_MODE_MAC, keylen * 8);

        res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA224, keylen * 8,
                                          &key_handle);

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

        res = TEE_PopulateTransientObject(key_handle, &attr, 1);

        res = TEE_SetOperationKey(op_handle, key_handle);

        TEE_MACInit(op_handle, NULL, 0);

        TEE_MACUpdate(op_handle, in, inlen);

        TEE_GetSystemTime(&t1);

        res = TEE_MACCompareFinal(op_handle, NULL, 0, out, outlen);

        TEE_GetSystemTime(&t2);

        sec = t2.seconds - t1.seconds;
        millisec = t2.millis - t1.millis;
        microsec = t2.micros - t1.micros;
        IMSG("Buffer size: %d\nVerified MAC(SHA224) in %d(s) %d(ms) %d(us)\n",
             inlen, sec, millisec, microsec);

        return res;
}

/* HMAC-SHA256 calculation */
static TEE_Result hmac_sha256(const uint8_t* key, const uint32_t keylen,
			      const char* in, const uint32_t inlen,
			      uint8_t* out, uint32_t outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	TEE_Time t1, t2;
	uint32_t sec, millisec;
	uint64_t microsec;

	/* Calculation procedure of HMAC-SHA256 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, keylen * 8);

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, keylen * 8,
					  &key_handle);
	
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	
	res = TEE_SetOperationKey(op_handle, key_handle);

	TEE_MACInit(op_handle, NULL, 0);

	TEE_MACUpdate(op_handle, in, inlen);

	TEE_GetSystemTime(&t1);

	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, &outlen);
	
	TEE_GetSystemTime(&t2);

	sec = t2.seconds - t1.seconds;
	millisec = t2.millis - t1.millis;
	microsec = t2.micros - t1.micros;
	IMSG("Buffer size: %d\nTagged MAC(SHA256) in %d(s) %d(ms) %d(us)\n",
	     inlen, sec, millisec, microsec);

	return res;
}

/* HMAC-SHA256 verification */
static TEE_Result verify_hmac_sha256(const uint8_t* key, const uint32_t keylen,
                                     const char* in, const uint32_t inlen,
                                     uint8_t* out, uint32_t outlen)
{
        TEE_Attribute attr = { 0 };
        TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
        TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
        TEE_Result res = TEE_SUCCESS;

        TEE_Time t1, t2;
        uint32_t sec, millisec;
        uint64_t microsec;

        /* Verification procedure of HMAC-SHA256 */
        res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256,
                                    TEE_MODE_MAC, keylen * 8);

        res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, keylen * 8,
                                          &key_handle);

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

        res = TEE_PopulateTransientObject(key_handle, &attr, 1);

        res = TEE_SetOperationKey(op_handle, key_handle);

        TEE_MACInit(op_handle, NULL, 0);

        TEE_MACUpdate(op_handle, in, inlen);

        TEE_GetSystemTime(&t1);

        res = TEE_MACCompareFinal(op_handle, NULL, 0, out, outlen);

        TEE_GetSystemTime(&t2);

        sec = t2.seconds - t1.seconds;
        millisec = t2.millis - t1.millis;
        microsec = t2.micros - t1.micros;
        IMSG("Buffer size: %d\nVerified MAC(SHA256) in %d(s) %d(ms) %d(us)\n",
             inlen, sec, millisec, microsec);

        return res;
}

/* HMAC-SHA384 calculation */
static TEE_Result hmac_sha384(const uint8_t* key, const uint32_t keylen,
			      const char* in, const uint32_t inlen,
			      uint8_t* out, uint32_t outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	TEE_Time t1, t2;
	uint32_t sec, millisec;
	uint64_t microsec;

	/* Calculation procedure of HMAC-SHA384 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA384,
				    TEE_MODE_MAC, keylen * 8);

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA384, keylen * 8,
					  &key_handle);
	
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	
	res = TEE_SetOperationKey(op_handle, key_handle);

	TEE_MACInit(op_handle, NULL, 0);

	TEE_MACUpdate(op_handle, in, inlen);

	TEE_GetSystemTime(&t1);

	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, &outlen);
	
	TEE_GetSystemTime(&t2);

	sec = t2.seconds - t1.seconds;
	millisec = t2.millis - t1.millis;
	microsec = t2.micros - t1.micros;
	IMSG("Buffer size: %d\nTagged MAC(SHA384) in %d(s) %d(ms) %d(us)\n",
	     inlen, sec, millisec, microsec);

	return res;
}

/* HMAC-SHA384 verification */
static TEE_Result verify_hmac_sha384(const uint8_t* key, const uint32_t keylen,
                                     const char* in, const uint32_t inlen,
                                     uint8_t* out, uint32_t outlen)
{
        TEE_Attribute attr = { 0 };
        TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
        TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
        TEE_Result res = TEE_SUCCESS;

        TEE_Time t1, t2;
        uint32_t sec, millisec;
        uint64_t microsec;

        /* Verification procedure of HMAC-SHA384 */
        res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA384,
                                    TEE_MODE_MAC, keylen * 8);

        res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA384, keylen * 8,
                                          &key_handle);

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

        res = TEE_PopulateTransientObject(key_handle, &attr, 1);

        res = TEE_SetOperationKey(op_handle, key_handle);

        TEE_MACInit(op_handle, NULL, 0);

        TEE_MACUpdate(op_handle, in, inlen);

        TEE_GetSystemTime(&t1);

        res = TEE_MACCompareFinal(op_handle, NULL, 0, out, outlen);

        TEE_GetSystemTime(&t2);

        sec = t2.seconds - t1.seconds;
        millisec = t2.millis - t1.millis;
        microsec = t2.micros - t1.micros;
        IMSG("Buffer size: %d\nVerified MAC(SHA384) in %d(s) %d(ms) %d(us)\n",
             inlen, sec, millisec, microsec);

        return res;
}

/* HMAC-SHA512 calculation */
static TEE_Result hmac_sha512(const uint8_t* key, const uint32_t keylen,
			      const char* in, const uint32_t inlen,
			      uint8_t* out, uint32_t outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	TEE_Time t1, t2;
	uint32_t sec, millisec;
	uint64_t microsec;

	/* Calculation procedure of HMAC-SHA512 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA512,
				    TEE_MODE_MAC, keylen * 8);

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA512, keylen * 8,
					  &key_handle);
	
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	
	res = TEE_SetOperationKey(op_handle, key_handle);

	TEE_MACInit(op_handle, NULL, 0);

	TEE_MACUpdate(op_handle, in, inlen);

	TEE_GetSystemTime(&t1);

	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, &outlen);
	
	TEE_GetSystemTime(&t2);

	sec = t2.seconds - t1.seconds;
	millisec = t2.millis - t1.millis;
	microsec = t2.micros - t1.micros;
	IMSG("Buffer size: %d\nTagged MAC(SHA512) in %d(s) %d(ms) %d(us)\n",
	     inlen, sec, millisec, microsec);

	return res;
}

/* HMAC-SHA512 verification */
static TEE_Result verify_hmac_sha512(const uint8_t* key, const uint32_t keylen,
                                     const char* in, const uint32_t inlen,
                                     uint8_t* out, uint32_t outlen)
{
        TEE_Attribute attr = { 0 };
        TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
        TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
        TEE_Result res = TEE_SUCCESS;

        TEE_Time t1, t2;
        uint32_t sec, millisec;
        uint64_t microsec;

        /* Verification procedure of HMAC-SHA512 */
        res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA512,
                                    TEE_MODE_MAC, keylen * 8);

        res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA512, keylen * 8,
                                          &key_handle);

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

        res = TEE_PopulateTransientObject(key_handle, &attr, 1);

        res = TEE_SetOperationKey(op_handle, key_handle);

        TEE_MACInit(op_handle, NULL, 0);

        TEE_MACUpdate(op_handle, in, inlen);

        TEE_GetSystemTime(&t1);

        res = TEE_MACCompareFinal(op_handle, NULL, 0, out, outlen);

        TEE_GetSystemTime(&t2);

        sec = t2.seconds - t1.seconds;
        millisec = t2.millis - t1.millis;
        microsec = t2.micros - t1.micros;
        IMSG("Buffer size: %d\nVerified MAC(SHA512) in %d(s) %d(ms) %d(us)\n",
             inlen, sec, millisec, microsec);

        return res;
}

/* Register shared key K */
static TEE_Result register_shared_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	/* Initialize shared key K */
	memset(K, 0, params[0].memref.size);
	/* Read shared key K from shared memory, copy into TA's memory */
	memcpy(K, params[0].memref.buffer, params[0].memref.size);

	K_len = params[0].memref.size;

	return res;
}

/* Get HMAC-SHA value */
static TEE_Result get_hmac(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t in[BUFFER_SIZE];
	uint32_t inlen;
	uint8_t mac1[SHA1_HASH_SIZE];
	uint8_t mac224[SHA224_HASH_SIZE];
	uint8_t mac256[SHA256_HASH_SIZE];
	uint8_t mac384[SHA384_HASH_SIZE];
	uint8_t mac512[SHA512_HASH_SIZE];
	uint32_t mac1_len = sizeof(mac1);
	uint32_t mac224_len = sizeof(mac224);
	uint32_t mac256_len = sizeof(mac256);
	uint32_t mac384_len = sizeof(mac384);
	uint32_t mac512_len = sizeof(mac512);

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	inlen = params[0].memref.size;

	/* Initialize TA's memory */
	memset(in, 0, params[0].memref.size);
	/* Read shared key K from shared memory, copy into TA's memory */
	memcpy(in, params[0].memref.buffer, params[0].memref.size);
	
	/* Calcuation HMAC-SHA1 */
	//res = hmac_sha1(K, K_len, in, inlen, mac1, mac1_len);

	/* Verification HMAC-SHA1 */
	//res = verify_hmac_sha1(K, K_len, in, inlen, mac1, mac1_len);

	/* Calcuation HMAC-SHA224 */
	//res = hmac_sha224(K, K_len, in, inlen, mac224, mac224_len);

	/* Verification HMAC-SHA224 */
        //res = verify_hmac_sha224(K, K_len, in, inlen, mac224, mac224_len);

	/* Calcuation HMAC-SHA256 */
	res = hmac_sha256(K, K_len, in, inlen, mac256, mac256_len);

	/* Verification HMAC-SHA256 */
        //res = verify_hmac_sha256(K, K_len, in, inlen, mac256, mac256_len);

	/* Calcuation HMAC-SHA384 */
	//res = hmac_sha384(K, K_len, in, inlen, mac384, mac384_len);

	/* Verification HMAC-SHA384 */
        //res = verify_hmac_sha384(K, K_len, in, inlen, mac384, mac384_len);

	/* Calcuation HMAC-SHA512 */
	//res = hmac_sha512(K, K_len, in, inlen, mac512, mac512_len);

	/* Verification HMAC-SHA512 */
        //res = verify_hmac_sha512(K, K_len, in, inlen, mac512, mac512_len);

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
		

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("MAC Tagging!\n");

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
	case TA_REGISTER_SHARED_KEY:
		return register_shared_key(param_types, params);
	case TA_GET_HMAC:
		return get_hmac(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;		
	}
}
