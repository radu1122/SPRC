/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "tema.h"

bool_t
xdr_sum_data (XDR *xdrs, sum_data *objp)
{
	register int32_t *buf;

	 if (!xdr_int (xdrs, &objp->x))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->y))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_req_auth_resp (XDR *xdrs, req_auth_resp *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->token, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_req_refresh_token_resp (XDR *xdrs, req_refresh_token_resp *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->token, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->refresh_token, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_access_token_req_struct (XDR *xdrs, access_token_req_struct *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->client_id, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->auth_token, ~0))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->refresh_token_needed))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->permission))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_access_token_res_struct (XDR *xdrs, access_token_res_struct *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->access_token, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->refresh_token, ~0))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->valability))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->error, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_validate_action_req_struct (XDR *xdrs, validate_action_req_struct *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->access_token, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->operation_type, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->resource, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_validate_action_res_struct (XDR *xdrs, validate_action_res_struct *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->resp, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_approve_auth_resp (XDR *xdrs, approve_auth_resp *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->token, ~0))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->permission))
		 return FALSE;
	return TRUE;
}
