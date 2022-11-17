#include <stdio.h>
#include <rpc/rpc.h>
#include <stdlib.h> 
#include <string.h>

#include "tema.h"
#define USER_NOT_FOUND "USER_NOT_FOUND"

#define PROTOCOL "tcp"

int main(int argc, char const *argv[])
{
	CLIENT *handle;

	if (argc != 2) {
		fprintf(stderr, "./client <fisier operatii>");
		return -1;
	}

	handle = clnt_create(argv[1], AUTH_PROG, AUTH_VERS, PROTOCOL);
	if (!handle) {
		perror("Failed to create client handle");
		clnt_pcreateerror(argv[0]);
		return -2;
	}


	// get data from file name argv[1]
	FILE *operations_file = fopen(argv[1], "r");

	if (!operations_file) {
		fprintf(stderr, "Error opening file %s.\n", argv[1]);
		return -1;
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	// while there are lines to read
	while ((read = getline(&line, &len, operations_file)) != -1) {
		line[strlen(line) - 1] = '\0';
		
		// split into tokens
		char *token = strtok(line, " ");
		char *tokens[3];
		int i = 0;
		while (token != NULL) {
			tokens[i] = token;
			token = strtok(NULL, " ");
			i++;
		}

		if (strcmp(tokens[1], "REQUEST")) {
			if (strcmp(tokens[2], "0")) {
				char *result = req_auth_1(&tokens[0], handle);
				if (strcmp(result, USER_NOT_FOUND)) {
					printf("USER_NOT_FOUND\n");
				} else {
					struct access_token_req_struct *req = malloc(sizeof(struct access_token_req_struct));
					req->client_id = tokens[0];
					req->auth_token = result;
					req->refresh_token_needed = 0;

					struct access_token_res_struct *res = req_access_token_1(req, handle);
				}
			}
		}

	// data.x = atoi(argv[2]);
	// data.y = atoi(argv[3]);

	// sum = get_sum_1(&data, handle);
	// if (!sum) {
	// 	perror("RPC failed");
	// 	return -3;
	// }
	// printf("%d + %d = %d\n", data.x, data.y, *sum);

	// clnt_destroy(handle);
	// xdr_free((xdrproc_t)xdr_int, (char *)sum);

	return 0;
}
