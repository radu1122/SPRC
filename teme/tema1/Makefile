RPC = rpcgen
CC = gcc
CFLAGS += -g -I/usr/include/tirpc
LDLIBS += -lnsl -ltirpc
PROGRAM = tema
SRC_SERVER = $(PROGRAM)_svc.c $(PROGRAM)_xdr.c
SRC_CLIENT = $(PROGRAM)_clnt.c $(PROGRAM)_xdr.c

.PHONY: build clean

build: server client

server: $(SRC_SERVER) $(PROGRAM)_rpc_server.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

client: $(SRC_CLIENT) $(PROGRAM)_rpc_client.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# $(SRC_SERVER) $(SRC_CLIENT): $(PROGRAM).x
# 	$(RPC) -C $^

clean:
	rm -f client server $(PROGRAM).h $(SRC_SERVER) $(SRC_CLIENT)
