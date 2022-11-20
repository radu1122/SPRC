CC = gcc
CFLAGS += -g -I/usr/include/tirpc
LDLIBS += -lnsl -ltirpc
PROGRAM = tema
SRC_SERVER = server.c tema_xdr.c
SRC_CLIENT = client.c tema_clnt.c tema_xdr.c 

.PHONY: build clean

build: server client

server: $(SRC_SERVER)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

client: $(SRC_CLIENT)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)


clean:
	rm -f client server server.out client.out