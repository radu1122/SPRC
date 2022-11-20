#include "tema.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/rpc.h>

#include "token.h"

#define USER_NOT_FOUND "USER_NOT_FOUND"

struct auth_token {
	char *client_id;
	char *token;
	int status; // 0 - ok, 1 - used
	char *permissionsStr;
};

struct access_token {
	char *client_id;
	char *token;
	char *refresh_token;
	int status; // 0 - ok, 1 - inactiv
	int valability; // 0 - not valid, != 0 - valid
	char *permissionsStr;
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
	memset(tokens, 0, 100 * sizeof(char *));
	int i = 0;

	token = strtok(strdup(approvals), ",");
	while (token != NULL) {
		tokens[i] = strdup(token);
		token = strtok(NULL, ",");
		i++;
	}

	return tokens;
}



int check_client(char *client) {
	for (int i = 0; i < number_of_clients; i++) {
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

struct req_auth_resp * req_auth_1_svc(char **argp, struct svc_req *rqstp) {
	char *client_id = *argp;
	printf("BEGIN %s AUTHZ\n", client_id);


	if (check_client(client_id) == 0) {
		static struct req_auth_resp resp;
		resp.token = USER_NOT_FOUND;
		return &resp;
	}

	char *token = generate_access_token(client_id);
	
	auth_tokens[auth_tokens_count].client_id = client_id;
	auth_tokens[auth_tokens_count].token = token;
	auth_tokens[auth_tokens_count].status = 0;
	auth_tokens[auth_tokens_count].permissionsStr = strdup("");
	auth_tokens_count++;


	static struct req_auth_resp result;
	result.token = token;
	return &result;
}

struct approve_auth_resp * req_approve_auth_1_svc(char **argp, struct svc_req *rqstp) {
	char *token = *argp;

	// check if token exists in auth_tokens
	int exists = 0;
	for (int i = 0; i < auth_tokens_count; i++) {
		if (strcmp(auth_tokens[i].token, token) == 0) {
			exists = 1;
			break;
		}
	}

	if (exists == 0) {
		static struct approve_auth_resp resp;
		resp.token = strdup("TOKEN_NOT_FOUND");
		resp.permission = 0;
		return &resp;
	}


	char * approval = strdup(approvals[current_approval]);
	current_approval++;
	if (strcmp(approval, "*,-") == 0) {
		static struct approve_auth_resp resp;
		resp.token = token;
		resp.permission = 0;
		return &resp;
	}

	// update auth_tokens permissions

	for (int i = 0; i < auth_tokens_count; i++) {
		if (strcmp(auth_tokens[i].token, token) == 0) {
			auth_tokens[i].permissionsStr = strdup(approval);
			break;
		}
	}

	static struct approve_auth_resp resp;
	resp.token = token;
	resp.permission = 1;
	return &resp;
}

struct req_refresh_token_resp * req_refresh_token_1_svc(char **argp, struct svc_req *rqstp) {
	char *refresh_token = *argp;

	int i;
	for (i = 0; i < access_tokens_count; i++) {
		if (strcmp(access_tokens[i].refresh_token, refresh_token) == 0) {
			printf("BEGIN %s AUTHZ REFRESH\n", access_tokens[i].client_id);
			access_tokens[i].status = 0;
			access_tokens[i].valability = valability;
			access_tokens[i].token = generate_access_token(refresh_token);
			access_tokens[i].refresh_token = generate_access_token(access_tokens[i].token);
			static struct req_refresh_token_resp resp;
			resp.token = strdup(access_tokens[i].token);
			resp.refresh_token = strdup(access_tokens[i].refresh_token);
			printf("  AccessToken = %s\n", access_tokens[i].token);
			printf("  RefreshToken = %s\n", access_tokens[i].refresh_token);
			return &resp;
		}
	}

	static struct req_refresh_token_resp resp;
	resp.token = strdup("ERROR");
	resp.refresh_token = strdup("ERROR");

	return &resp;
}


struct access_token_res_struct * req_access_token_1_svc(struct access_token_req_struct *argp, struct svc_req *rqstp) {
	static struct access_token_res_struct result;
	char *client_id = argp->client_id;
	char *auth_token = argp->auth_token;
	int refresh_token_needed = argp->refresh_token_needed;	
	printf("  RequestToken = %s\n", auth_token);

	if (argp->permission == 0) {
		result.access_token = strdup("");
		result.refresh_token = strdup("");
		result.valability = 0;
		result.error = "REQUEST_DENIED";
		return &result;
	}

	for (int i = 0; i < auth_tokens_count; i++) {
		if (strcmp(auth_tokens[i].client_id, client_id) == 0 && strcmp(auth_tokens[i].token, auth_token) == 0 && auth_tokens[i].status == 0) {
			auth_tokens[i].status = 1;
			char *access_token = generate_access_token(auth_token);
			result.access_token = access_token;
			result.valability = valability;
			result.error = strdup("");

			access_tokens[access_tokens_count].client_id = strdup(client_id);
			access_tokens[access_tokens_count].token = access_token;
			access_tokens[access_tokens_count].status = 0;
			access_tokens[access_tokens_count].valability = valability;
			access_tokens[access_tokens_count].permissionsStr = auth_tokens[i].permissionsStr;

			printf("  AccessToken = %s\n", access_token);

			if (refresh_token_needed == 1) {
				char *refresh_token = generate_access_token(access_token);
				result.refresh_token = refresh_token;
				access_tokens[access_tokens_count].refresh_token = refresh_token;
				printf("  RefreshToken = %s\n", refresh_token);
			} else {
				result.refresh_token = strdup("");
				access_tokens[access_tokens_count].refresh_token = strdup("");
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

struct validate_action_res_struct * req_validate_action_1_svc(struct validate_action_req_struct *argp, struct svc_req *rqstp) {
	char *result;
	char *access_token = argp->access_token;
	char *operation_type = argp->operation_type;
	char *resource = argp->resource;

	for (int i = access_tokens_count - 1; i >= 0; i--) {
		if (strcmp(access_tokens[i].token, access_token) == 0 && access_tokens[i].status == 0) {
			if (access_tokens[i].valability == 0) {
				if (strcmp(access_tokens[i].refresh_token, "") == 0) {
					printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, "", access_tokens[i].valability);
				}
				static struct validate_action_res_struct resp;
				resp.resp = "TOKEN_EXPIRED";
				return &resp;
			}
			access_tokens[i].valability = access_tokens[i].valability - 1;

			if (check_resource(resource) == 0) {
				printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, access_token, access_tokens[i].valability);
				static struct validate_action_res_struct resp;
				resp.resp = "RESOURCE_NOT_FOUND";
				return &resp;
			}

			char *approval = strdup(access_tokens[i].permissionsStr);


			if (strcmp(approval, "*,-") == 0) {
				printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, access_token, access_tokens[i].valability);
				static struct validate_action_res_struct resp;
				resp.resp = "OPERATION_NOT_PERMITTED";
				return &resp;
			}

			// split approvals by ,
			char **tokens = split_approvals(approval);
			int tokens_length = strlen((char *)tokens);


			int op_permitted = 0;			
			int j = 0;
			while (1) {
				if (tokens[j] == NULL || tokens[j + 1] == NULL) {
					break;
				}

				if(strcmp(tokens[j], resource) == 0) {
					// check if operation_type[0] exists in tokens[j+1]
					if (operation_type[0] == 'E' && strchr(tokens[j+1], 'X') != NULL) {
						op_permitted = 1;
						break;
					}
					if (strchr(tokens[j+1], operation_type[0]) != NULL) {
						op_permitted = 1;
						break;
					}
				}
				j = j + 2;
			}

			if (op_permitted == 0) {
				printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, access_token, access_tokens[i].valability);
				free(tokens);
				static struct validate_action_res_struct resp;
				resp.resp = "OPERATION_NOT_PERMITTED";
				return &resp;
			}

			free(tokens);


			printf("PERMIT (%s,%s,%s,%d)\n", operation_type, resource, access_token, access_tokens[i].valability);

			static struct validate_action_res_struct resp;
			resp.resp = "PERMISSION_GRANTED";
			return &resp;
		}
	}

	printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, "", 0);

	static struct validate_action_res_struct resp;
	resp.resp = "PERMISSION_DENIED";
	return &resp;
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
	number_of_clients = 0;
	while ((read = getline(&line, &len, clientsFile)) != -1) {
		if (line[strlen(line) - 1] == '\n') {
			line[strlen(line) - 1] = '\0';
		}
		strcpy(clients[number_of_clients], line);
		number_of_clients++;
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
	number_of_resources = 0;
	while ((read = getline(&line, &len, resourcesFile)) != -1) {
		if (line[strlen(line) - 1] == '\n') {
			line[strlen(line) - 1] = '\0';
		}
		strcpy(resources[number_of_resources], line);
		number_of_resources++;
	}

	fclose(resourcesFile);

	// read from file argv[3] and populate approvals array
	FILE* approvalsFile = fopen(argv[3], "r");
	if (!approvalsFile) {
		fprintf(stderr, "Error opening file %s.\n", argv[3]);
		return -1;
	}

	number_of_approvals = 0;
	while ((read = getline(&line, &len, approvalsFile)) != -1) {
		if (line[strlen(line) - 1] == '\n') {
			line[strlen(line) - 1] = '\0';
		}
		strcpy(approvals[number_of_approvals], line);
		number_of_approvals++;
	}

	fclose(approvalsFile);

	FILE* ttlFile = fopen(argv[4], "r");
	if (!ttlFile) {
		fprintf(stderr, "Error opening file %s.\n", argv[3]);
		return -1;
	}

	read = getline(&line, &len, clientsFile);
	if (read == -1) {
		fprintf(stderr, "Error reading file %s.\n", argv[1]);
		return -1;
	}

	valability = atoi(line);
	return 0;
}

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

static void
auth_prog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		char *req_auth_1_arg;
		char *req_approve_auth_1_arg;
		struct access_token_req_struct req_access_token_1_arg;
		char *req_refresh_token_1_arg;
		struct validate_action_req_struct req_validate_action_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case req_auth:
		_xdr_argument = (xdrproc_t) xdr_wrapstring;
		_xdr_result = (xdrproc_t) xdr_req_auth_resp;
		local = (char *(*)(char *, struct svc_req *)) req_auth_1_svc;
		break;

	case req_approve_auth:
		_xdr_argument = (xdrproc_t) xdr_wrapstring;
		_xdr_result = (xdrproc_t) xdr_approve_auth_resp;
		local = (char *(*)(char *, struct svc_req *)) req_approve_auth_1_svc;
		break;

	case req_access_token:
		_xdr_argument = (xdrproc_t) xdr_access_token_req_struct;
		_xdr_result = (xdrproc_t) xdr_access_token_res_struct;
		local = (char *(*)(char *, struct svc_req *)) req_access_token_1_svc;
		break;

	case req_refresh_token:
		_xdr_argument = (xdrproc_t) xdr_wrapstring;
		_xdr_result = (xdrproc_t) xdr_req_refresh_token_resp;
		local = (char *(*)(char *, struct svc_req *)) req_refresh_token_1_svc;
		break;

	case req_validate_action:
		_xdr_argument = (xdrproc_t) xdr_validate_action_req_struct;
		_xdr_result = (xdrproc_t) xdr_validate_action_res_struct;
		local = (char *(*)(char *, struct svc_req *)) req_validate_action_1_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

int
main (int argc, char **argv)
{
	setbuf(stdout, NULL);
	if (populate_db(argc, argv) == -1) {
		return -1;
	}
	register SVCXPRT *transp;

	pmap_unset (AUTH_PROG, AUTH_VERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTH_PROG, AUTH_VERS, auth_prog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (AUTH_PROG, AUTH_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTH_PROG, AUTH_VERS, auth_prog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (AUTH_PROG, AUTH_VERS, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}