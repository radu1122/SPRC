struct sum_data {
	int x;
	int y;
};

struct access_token_req_struct {
	string client_id<>;
	string auth_token<>;
};


struct access_token_res_struct {
	string access_token<>;
	string refresh_token<>;
	int expires_in;
	string error<>;
};

struct validate_action_req_struct {
	string access_token<>;
	string opeation_type<>;
	string resource<>;
};

program AUTH_PROG {
	version AUTH_VERS {
		string req_auth(string) = 1;
		struct access_token_res_struct req_access_token(struct access_token_req_struct) = 2;
		string req_validate_action(struct validate_action_req_struct) = 3;
	} = 1;
} = 1;
