#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <kdw_rsa_ta.h>

float time_diff(struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec) + 1e-6 * (end->tv_usec - start->tv_usec);
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = { 0 };
	TEEC_UUID uuid = TA_KDW_RSA_UUID;

	uint32_t err_origin;

	struct timeval start, end;

	uint8_t buf[] = {0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
			 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
			 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
			 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75
	};

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Initialize the TEEC_Operation */
	memset(&op, 0, sizeof(op));

	/* RSA Implementation */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = sizeof(buf);

	gettimeofday(&start, NULL);
	res = TEEC_InvokeCommand(&sess, TA_GET_RSA, &op, &err_origin);
	gettimeofday(&end, NULL);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

	printf("RSA Signing Complete!\n");
	printf("Total Execution time: %0.6f(s)\n", time_diff(&start, &end));

exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	
	return 0;
}
