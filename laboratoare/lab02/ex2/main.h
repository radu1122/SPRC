/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _MAIN_H_RPCGEN
#define _MAIN_H_RPCGEN

#define RPCGEN_VERSION	199506

#include <rpc/rpc.h>


struct student {
	char *nume;
	char *grupa;
};
typedef struct student student;
#ifdef __cplusplus
extern "C" bool_t xdr_student(XDR *, student*);
#elif __STDC__
extern  bool_t xdr_student(XDR *, student*);
#else /* Old Style C */
bool_t xdr_student();
#endif /* Old Style C */


#define CHECK_PROG ((rpc_uint)0x31234567)
#define CHECK_VERS ((rpc_uint)1)

#ifdef __cplusplus
#define grade ((rpc_uint)1)
extern "C" char ** grade_1(struct student *, CLIENT *);
extern "C" char ** grade_1_svc(struct student *, struct svc_req *);

#elif __STDC__
#define grade ((rpc_uint)1)
extern  char ** grade_1(struct student *, CLIENT *);
extern  char ** grade_1_svc(struct student *, struct svc_req *);

#else /* Old Style C */
#define grade ((rpc_uint)1)
extern  char ** grade_1();
extern  char ** grade_1_svc();
#endif /* Old Style C */

#endif /* !_MAIN_H_RPCGEN */
