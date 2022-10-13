#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <kdw_mac_ta.h>

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
	TEEC_UUID uuid = TA_KDW_MAC_UUID;

	uint32_t err_origin;

	struct timeval start, end;
	
	/* rfc4868 test vector (test case 2.7.2.1 (AUTH256-2)) */
	uint8_t K[] = {0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
		       0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
		       0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
		       0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65
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

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
					 
	/* Write into shared memory */
	op.params[0].tmpref.buffer= K; /* Shared key K */
	op.params[0].tmpref.size = sizeof(K); /* Size of shared key K */

	fprintf(stdout, "Register the shared key: %s\n", K);
	res = TEEC_InvokeCommand(&sess, TA_REGISTER_SHARED_KEY, &op, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		goto exit;
	}

	/* Initialize the TEEC_Operation */
	memset(&op, 0, sizeof(op));

	/* 2. Get HMAC */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	uint8_t *line;
	uint8_t buf[2048];
	
	gettimeofday(&start, NULL);
	FILE *fp = fopen("/root/tiny_one.csv", "r");
	if (fp != NULL)
	{
		gettimeofday(&start, NULL);
		while (!feof(fp))
		{
			line = fgets(buf, sizeof(buf), fp);

			if (line == NULL)
				break;
			
			// Write into shared memory
			op.params[0].tmpref.buffer = line;
			op.params[0].tmpref.size = strlen(line);
			
			res = TEEC_InvokeCommand(&sess, TA_GET_HMAC,
						  &op, &err_origin);
						  
			if (res != TEEC_SUCCESS)
				errx(1,
				"TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		}
	}
	gettimeofday(&end, NULL);
	fclose(fp);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

	printf("MAC Tagging Complete!\n");
	printf("Total Execution time: %0.6f(s)\n", time_diff(&start, &end));
	
exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
