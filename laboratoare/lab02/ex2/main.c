#include <stdio.h>
#include <stdlib.h>

#include "main.h"

int main(int argc, char const *argv[])
{
	CLIENT *handle;
	char **resp;
	struct student stud;


	handle = clnt_create("rpc.sprc.dfilip.xyz", CHECK_PROG, CHECK_VERS, "tcp");
	if (!handle) {
		perror("handle err");
		return -1;
	}

	stud.nume = "Radu";
	stud.grupa = "341CA";

	resp = grade_1(&stud, handle);
	if (!resp) {
		perror("RPC call err");
		return -1;
	}

    printf("Response: %s\n", *resp);

	clnt_destroy(handle);
	free(*resp);
	xdr_free((xdrproc_t)xdr_char, (char *)resp);

	return 0;
}