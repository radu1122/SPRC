#include <stdio.h>
#include <rpc/rpc.h>
#include <stdlib.h> 

#include "tema.h"

#define PROTOCOL "tcp"

int main(int argc, char const *argv[])
{
	CLIENT *handle;
	int *sum;
	struct sum_data data;

	if (argc != 4) {
		fprintf(stderr, "Usage:\n\t%s <SERVER_ADDRESS> <NUMBER1> <NUMBER2>\n",
			argv[0]);
		return -1;
	}

	handle = clnt_create(argv[1], AUTH_PROG, AUTH_VERS, PROTOCOL);
	if (!handle) {
		perror("Failed to create client handle");
		clnt_pcreateerror(argv[0]);
		return -2;
	}

	data.x = atoi(argv[2]);
	data.y = atoi(argv[3]);

	sum = get_sum_1(&data, handle);
	if (!sum) {
		perror("RPC failed");
		return -3;
	}
	printf("%d + %d = %d\n", data.x, data.y, *sum);

	clnt_destroy(handle);
	xdr_free((xdrproc_t)xdr_int, (char *)sum);

	return 0;
}
