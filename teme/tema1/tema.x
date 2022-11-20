struct sum_data {
	int x;
	int y;
};

struct req_auth_resp {
	string token<>;
};

struct req_refresh_token_resp {
	string token<>;
};

struct access_token_req_struct {
	string client_id<>;
	string auth_token<>;
	int refresh_token_needed;
	int permission;
};


struct access_token_res_struct {
	string access_token<>;
	string refresh_token<>;
	int valability;
	string error<>;
};

struct validate_action_req_struct {
	string client_id<>;
	string access_token<>;
	string operation_type<>;
	string resource<>;
};

struct validate_action_res_struct {
	string resp<>;
};

struct approve_auth_resp {
	string token<>;
	int permission;
};



program AUTH_PROG {
	version AUTH_VERS {
		struct req_auth_resp req_auth(string) = 1;
		struct approve_auth_resp req_approve_auth(string) = 2;

		struct access_token_res_struct req_access_token(struct access_token_req_struct) = 3;

		struct req_refresh_token_resp req_refresh_token(string) = 4;

		struct validate_action_res_struct req_validate_action(struct validate_action_req_struct) = 5;
	} = 1;
} = 1;
