#include <rpc/rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tema.h"
#include "token.h"

#define USER_NOT_FOUND "USER_NOT_FOUND"

struct auth_token {
	char *client_id;
	char *token;
	int status; // 0 - ok, 1 - used
};

struct access_token {
	char *client_id;
	char *token;
	char *refresh_token;
	int status; // 0 - ok, 1 - inactiv
	int valability; // 0 - not valid, != 0 - valid
};

int number_of_clients = 0;
char clients[1024][100];

int number_of_resources = 0;
char resources[1024][100];

int number_of_approvals = 0;
int current_approval = 0;
char approvals[1024][100];

int valability;

int auth_tokens_count = 0;
struct auth_token auth_tokens[1024];

int access_tokens_count = 0;
struct access_token access_tokens[1024];



char **split_approvals(char *approvals) {
	char *token;
	char **tokens = malloc(100 * sizeof(char *));
	int i = 0;

	token = strtok(approvals, ",");
	while (token != NULL) {
		tokens[i] = token;
		token = strtok(NULL, ",");
		i++;
	}

	return tokens;
}



int check_client(char *client) {
	int i;
	for (i = 0; i < number_of_clients; i++) {
		if (strcmp(clients[i], client) == 0) {
			return 1;
		}
	}
	return 0;
}

int check_resource(char *resource) {
	int i;
	for (i = 0; i < number_of_resources; i++) {
		if (strcmp(resources[i], resource) == 0) {
			return 1;
		}
	}
	return 0;
}

char **req_auth_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	char *client_id = *argp;

	if (check_client(client_id) != 0) {
		return USER_NOT_FOUND;
	}

	char *token = generate_access_token(client_id);
	
	auth_tokens[auth_tokens_count].client_id = client_id;
	auth_tokens[auth_tokens_count].token = token;
	auth_tokens[auth_tokens_count].status = 0;
	auth_tokens_count++;

	return token;
}

struct access_token_res_struct * req_access_token_1_svc(struct access_token_req_struct *argp, struct svc_req *rqstp) {
	struct access_token_res_struct result;
	char *client_id = argp->client_id;
	char *auth_token = argp->auth_token;
	int refresh_token_needed = argp->refresh_token_needed;
	printf("BEGIN %s AUTHZ\n", client_id);
	printf("\tRequestToken = %s\n", auth_token);

	int i;
	for (i = 0; i < auth_tokens_count; i++) {
		if (strcmp(auth_tokens[i].client_id, client_id) == 0 && strcmp(auth_tokens[i].token, auth_token) == 0 && auth_tokens[i].status == 0) {
			auth_tokens[i].status = 1;
			char *access_token = generate_access_token(auth_token);
			char *refresh_token = generate_access_token(access_token);
			result.access_token = access_token;
			result.valability = valability;
			result.error = NULL;

			access_tokens[access_tokens_count].client_id = client_id;
			access_tokens[access_tokens_count].token = access_token;
			access_tokens[access_tokens_count].status = 0;
			access_tokens[access_tokens_count].valability = valability;

			printf("\tAccess Token = %s\n", access_token);

			if (refresh_token_needed == 1) {
				result.refresh_token = refresh_token;
				access_tokens[access_tokens_count].refresh_token = refresh_token;
				printf("\tRefresh Token = %s\n", refresh_token);
			} else {
				result.refresh_token = NULL;
				access_tokens[access_tokens_count].refresh_token = NULL;
			}

			access_tokens_count++;


			
			return &result;
		}
	}

	result.access_token = NULL;
	result.refresh_token = NULL;
	result.valability = 0;
	result.error = "REQUEST_DENIED";
	return &result;
}

char ** req_validate_action_1_svc(struct validate_action_req_struct *argp, struct svc_req *rqstp) {
	char *result;
	char *client_id = argp->client_id;
	char *access_token = argp->access_token;
	char *operation_type = argp->operation_type;
	char *resource = argp->resource;

	int i;
	for (i = 0; i < access_tokens_count; i++) {
		if (strcmp(access_tokens[i].client_id, client_id) == 0 && strcmp(access_tokens[i].token, access_token) == 0 && access_tokens[i].status == 0) {
			if (access_tokens[i].valability <= 0 && access_tokens[i].refresh_token != NULL) {
				access_tokens[i].valability--;
				result = "TOKEN_EXPIRED";
				printf("DENY (%s, %s, %s, %d)", operation_type, resource, access_token, access_tokens[i].valability);
				return &result;
			} else {
				// TODO refresh token
				access_tokens[i].valability = valability;
				access_tokens[i].status = 0;
				access_tokens[i].token = generate_access_token(access_token[i].refresh_token);
				acces_tokens[i].refresh_token = generate_access_token(access_tokens[i].token);
				// print BEGIN Cli e n t 1 AUTHZ REFRESH
				printf("BEGIN %s AUTHZ REFRESH\n", client_id);
				printf("\t Access Token = %s\n", access_tokens[i].token);
				printf("\tRefresh Token = %s\n", access_tokens[i].refresh_token);
			}

			if (check_resource(resource) == 0) {
				printf("DENY (%s, %s, %s, %d)", operation_type, resource, access_token, access_tokens[i].valability);
				result = "RESOURCE_NOT_FOUND";
				return &result;
			}

			char *client_id = access_tokens[i].client_id;


			if (strcmp(approvals[current_approval], "*,-") == 0) {
				printf("DENY (%s, %s, %s, %d)", operation_type, resource, access_token, access_tokens[i].valability);
				result = "OPERATION_NOT_PERMITTED";
				return &result;
			}

			// split approvals by ,
			char **tokens = split_approvals(approvals[current_approval]);
			int tokens_length = strlen(tokens);

			int op_permitted = 0;			
			for (int j = 0; j < tokens_length; j += 2) {
				if(strcmp(tokens[j], resource) == 0) {
					if (strcmp(tokens[j+1], operation_type) == 0) {
						op_permitted = 1;
						break;
					}
				}
			}

			if (op_permitted == 0) {
				result = "OPERATION_NOT_PERMITTED";
				printf("DENY (%s, %s, %s, %d)", operation_type, resource, access_token, access_tokens[i].valability);
				free(tokens);
				return &result;
			}

			free(tokens);

			if (access_tokens[i].refresh_token != NULL) {
				access_tokens[i].valability--;
			}

			if (access_tokens[i].valability == 0) {
				access_tokens[i].status = 1;
			}
			printf("PERMIT (%s, %s, %s, %d)", operation_type, resource, access_token, access_tokens[i].valability);

			result = "PERMISSION_GRANTED";
			return &result;
		}
	}

	printf("DENY (%s, %s, %s, %d)", operation_type, resource, access_token, access_tokens[i].valability);

	result = "PERMISSION_DENIED";
	return &result;
}

int populate_db(int argc, char* argv[]) {
	// populate db

	if (argc != 5) {
		fprintf(stderr, "./server <fisier clienti> <fisier resurse> <fisier aprobari> <valabilitate jetoane>\n");
		return -1;
	}

	// read from file argv[1]
	FILE* clientsFile = fopen(argv[1], "r");
	if (!clientsFile) {
		fprintf(stderr, "Error opening file %s.\n", argv[1]);
		return -1;
	}

	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	
	// read first line and get number of clients
	read = getline(&line, &len, clientsFile);
	if (read == -1) {
		fprintf(stderr, "Error reading file %s.\n", argv[1]);
		return -1;
	}

	number_of_clients = atoi(line);

	// read the rest of the lines and populate clients array
	int i = 0;
	while ((read = getline(&line, &len, clientsFile)) != -1) {
		line[strlen(line) - 1] = '\0';
		strcpy(clients[i], line);
		i++;
	}

	fclose(clientsFile);

	// read from file argv[2]
	FILE* resourcesFile = fopen(argv[2], "r");
	if (!resourcesFile) {
		fprintf(stderr, "Error opening file %s.\n", argv[2]);
		return -1;
	}

	// read first line and get number of resources
	read = getline(&line, &len, resourcesFile);

	if (read == -1) {
		fprintf(stderr, "Error reading file %s.\n", argv[2]);
		return -1;
	}

	number_of_resources = atoi(line);

	// read the rest of the lines and populate resources array
	i = 0;
	while ((read = getline(&line, &len, resourcesFile)) != -1) {
		line[strlen(line) - 1] = '\0';
		strcpy(resources[i], line);
		i++;
	}

	fclose(resourcesFile);

	// read from file argv[3] and populate approvals array
	FILE* approvalsFile = fopen(argv[3], "r");
	if (!approvalsFile) {
		fprintf(stderr, "Error opening file %s.\n", argv[3]);
		return -1;
	}

	i = 0;
	while ((read = getline(&line, &len, approvalsFile)) != -1) {
		line[strlen(line) - 1] = '\0';
		strcpy(approvals[i], line);
		i++;
	}
	number_of_approvals = i;

	fclose(approvalsFile);

	valability = atoi(argv[4]);
	return 0;
}
