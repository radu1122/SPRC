#include <stdio.h>
#include <rpc/rpc.h>
#include <stdlib.h> 
#include <string.h>

#include "tema.h"
#define USER_NOT_FOUND "USER_NOT_FOUND"

#define PROTOCOL "udp"

struct access_token_struct {
	char *client_id;
	char *access_token;
	char *refresh_token;
	int valability;
};

int access_tokens_count = 0;
struct access_token_struct access_tokens[1024];

char **split_string(char *string) {
	char **result = malloc(1024 * sizeof(char *));
	memset(result, 0, 1024 * sizeof(char *));
	char *token = strtok(strdup(string), ",");
	int i = 0;
	while (token != NULL) {
		result[i] = strdup(token);
		token = strtok(NULL, ",");
		i++;
	}
	result[i] = NULL;
	return result;
}

int main(int argc, char const *argv[])
{
	CLIENT *handle;

	if (argc != 3) {
		fprintf(stderr, "./client <server address> <fisier operatii>\n");
		return -1;
	}

	handle = clnt_create(argv[1], AUTH_PROG, AUTH_VERS, PROTOCOL);
	if (!handle) {
		perror("Failed to create client handle");
		clnt_pcreateerror(argv[0]);
		return -2;
	}


	// get data from file name argv[1]
	FILE *operations_file = fopen(argv[2], "r");

	if (!operations_file) {
		fprintf(stderr, "Error opening file %s.\n", argv[2]);
		return -1;
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	// while there are lines to read
	while ((read = getline(&line, &len, operations_file)) != -1) {

		// line[strlen(line) - 1] = '\0';

		// printf("Line: %s", line);m
		
		// split into tokens
		char ** tokens = split_string(line);
		// printf("Tokens: %s %s %s\n", tokens[0], tokens[1], tokens[2]);

		if (tokens[2][strlen(tokens[2]) - 1] == '\n') {
			tokens[2][strlen(tokens[2]) - 1] = '\0';
		}


		if (strcmp(tokens[1], "REQUEST") == 0) {
			struct req_auth_resp * result = req_auth_1(&tokens[0], handle);
			struct access_token_req_struct *req = malloc(sizeof(struct access_token_req_struct));
			req->client_id = tokens[0];
			req->auth_token = result->token;
			if (strcmp(tokens[2], "0") == 0) {
				req->refresh_token_needed = 0;
			} else {
				req->refresh_token_needed = 1;
			}
			if (strcmp(result->token, USER_NOT_FOUND) == 0) {
				printf("USER_NOT_FOUND\n");
			} else {

				struct approve_auth_resp *approve_result = req_approve_auth_1(&result->token, handle);

				// if (approve_result->permission == 1) {
					req->permission = approve_result->permission;
					struct access_token_res_struct *res = req_access_token_1(req, handle);

					if (strcmp(res->error, "REQUEST_DENIED") == 0) {
						printf("REQUEST_DENIED\n");
					} else {
						access_tokens[access_tokens_count].client_id = tokens[0];
						access_tokens[access_tokens_count].access_token = res->access_token;
						access_tokens[access_tokens_count].refresh_token = res->refresh_token;
						access_tokens[access_tokens_count].valability = res->valability;
						access_tokens_count++;
						if (strcmp(res->refresh_token, "") == 0) {
							printf("%s -> %s\n", result->token, res->access_token);
						} else {
							printf("%s -> %s,%s\n", result->token, res->access_token, res->refresh_token);
						}
					}
				// } else {
				// 	printf("Permission denied\n");
				// }

				
			}
			free(req);
		} else {
			// get access token of client tokens[0]
			char *access_token = strdup("NO_TOKEN");
			char *refresh_token = strdup("NO_TOKEN");
			for (int i = access_tokens_count - 1; i >= 0; i--) {
				// print accestoken and client id
				if (strcmp(access_tokens[i].client_id, tokens[0]) == 0) {
					access_token = strdup(access_tokens[i].access_token);
					refresh_token = strdup(access_tokens[i].refresh_token);
					break;
				}
			}


			// send req_validate_action_1
			struct validate_action_req_struct *req = malloc(sizeof(struct validate_action_req_struct));
			req->access_token = strdup(access_token);
			req->operation_type = strdup(tokens[1]);
			req->resource = tokens[2];

			struct validate_action_res_struct * res = req_validate_action_1(req, handle);

			if (strcmp(res->resp, "TOKEN_EXPIRED") == 0 && strcmp(refresh_token, "") != 0) {
				struct req_refresh_token_resp *refresh_res = req_refresh_token_1(&refresh_token, handle);
				req->access_token = strdup(refresh_res->token);

				// update access token
				for (int i = access_tokens_count - 1; i >= 0; i--) {
					if (strcmp(access_tokens[i].client_id, tokens[0]) == 0) {
						access_tokens[i].access_token = strdup(refresh_res->token);
						access_tokens[i].refresh_token = strdup(refresh_res->refresh_token);
						break;
					}
				}

				res = req_validate_action_1(req, handle);
			}

			printf("%s\n", res->resp);
			free(req);
		}

		free(tokens);
	}

	// data.x = atoi(argv[2]);
	// data.y = atoi(argv[3]);

	// sum = get_sum_1(&data, handle);
	// if (!sum) {
	// 	perror("RPC failed");
	// 	return -3;
	// }
	// printf("%d + %d = %d\n", data.x, data.y, *sum);

	clnt_destroy(handle);

	return 0;
}
