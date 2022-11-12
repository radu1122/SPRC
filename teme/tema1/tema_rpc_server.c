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

int number_of_clients = 0;
char clients[1024][100];

int number_of_resources = 0;
char resources[1024][100];

int number_of_approvals = 0;
char approvals[1024][100];

int valability;

int auth_tokens_count = 0;
struct auth_token auth_tokens[1024];





int check_client(char *client) {
	int i;
	for (i = 0; i < number_of_clients; i++) {
		if (strcmp(clients[i], client) == 0) {
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

int populate_db(char* argv[]) {
	// populate db

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
