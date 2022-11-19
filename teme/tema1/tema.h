/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _TEMA_H_RPCGEN
#define _TEMA_H_RPCGEN

#include <rpc/rpc.h>


#ifdef __cplusplus
extern "C" {
#endif


struct sum_data {
	int x;
	int y;
};
typedef struct sum_data sum_data;

struct access_token_req_struct {
	char *client_id;
	char *auth_token;
	int refresh_token_needed;
};
typedef struct access_token_req_struct access_token_req_struct;

struct access_token_res_struct {
	char *access_token;
	char *refresh_token;
	int valability;
	char *error;
};
typedef struct access_token_res_struct access_token_res_struct;

struct validate_action_req_struct {
	char *client_id;
	char *access_token;
	char *operation_type;
	char *resource;
};
typedef struct validate_action_req_struct validate_action_req_struct;

#define AUTH_PROG 1
#define AUTH_VERS 1

#if defined(__STDC__) || defined(__cplusplus)
#define req_auth 1
extern  char ** req_auth_1(char **, CLIENT *);
extern  char ** req_auth_1_svc(char **, struct svc_req *);
#define req_access_token 2
extern  struct access_token_res_struct * req_access_token_1(struct access_token_req_struct *, CLIENT *);
extern  struct access_token_res_struct * req_access_token_1_svc(struct access_token_req_struct *, struct svc_req *);
#define req_validate_action 3
extern  char ** req_validate_action_1(struct validate_action_req_struct *, CLIENT *);
extern  char ** req_validate_action_1_svc(struct validate_action_req_struct *, struct svc_req *);
extern int auth_prog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define req_auth 1
extern  char ** req_auth_1();
extern  char ** req_auth_1_svc();
#define req_access_token 2
extern  struct access_token_res_struct * req_access_token_1();
extern  struct access_token_res_struct * req_access_token_1_svc();
#define req_validate_action 3
extern  char ** req_validate_action_1();
extern  char ** req_validate_action_1_svc();
extern int auth_prog_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_sum_data (XDR *, sum_data*);
extern  bool_t xdr_access_token_req_struct (XDR *, access_token_req_struct*);
extern  bool_t xdr_access_token_res_struct (XDR *, access_token_res_struct*);
extern  bool_t xdr_validate_action_req_struct (XDR *, validate_action_req_struct*);

#else /* K&R C */
extern bool_t xdr_sum_data ();
extern bool_t xdr_access_token_req_struct ();
extern bool_t xdr_access_token_res_struct ();
extern bool_t xdr_validate_action_req_struct ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_TEMA_H_RPCGEN */
