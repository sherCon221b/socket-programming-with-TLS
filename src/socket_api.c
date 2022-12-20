#include "socket_api.h"

struct sockaddr_in get_address_to_bind_server(int port)
{
	// Prepare the sockaddr_in structure
	struct sockaddr_in sock_address;

	sock_address.sin_family = AF_INET;
	sock_address.sin_addr.s_addr = INADDR_ANY;
	sock_address.sin_port = htons(port);

	return sock_address;
}

// Create socket
RET_CODE create_socket(SOCKET *sock_desc)
{	
	RET_CODE ret = OK;

	*sock_desc = socket(AF_INET, SOCK_STREAM, 0);
	if(ret==FAIL) {
		perror("Creating socketing: [FAILED]\n");
		ret = ERR_SOCKET_CREATE;
	}

	return ret;
}

RET_CODE connect_sock_to_address(SOCKET *sock_desc, struct sockaddr_in *addr)
{
	RET_CODE ret = OK;

	ret = connect(*sock_desc, (struct sockaddr *)addr , sizeof(*addr));
	if(ret==FAIL) {
		perror("Connecting Socket to Address: [FAILED]\n");
		ret = ERR_SOCKET_CONNECT;
	}
	return ret;
}

RET_CODE set_sock_opt(SOCKET *socket)
{
	RET_CODE ret = OK;

	ret = setsockopt(*socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	if(ret==FAIL) {
		perror("Setting the option specified: [FAILED] \n");
		ret = ERR_SOCKET_SET_OPT;
	}
	return ret;
}

RET_CODE bind_sock_to_address(SOCKET *socket, struct sockaddr_in *addr)
{	
	RET_CODE ret = OK;

	ret = bind(*socket,(struct sockaddr *)addr , sizeof(*addr));
	if(ret==FAIL) {
		perror("Binding socket to address: [FAILED]\n");
		ret = ERR_SOCKET_BIND_TO_ADDR;
	}
	return ret;
}

RET_CODE listen_to_socket(SOCKET *socket)
{	
	RET_CODE ret = OK;

	ret = listen(*socket, BACKLOG);
	if(ret==FAIL) {
		perror("Listening to socket: [FAILED]\n");
		ret = ERR_SOCKET_LISTEN;
	}
	return ret;
}

RET_CODE accept_client(SOCKET *socket, struct sockaddr_in *client, int * addr_len)
{	
	RET_CODE ret = OK;

	ret = accept(*socket, (struct sockaddr *)client, (socklen_t*)addr_len);
	if(ret==FAIL) {
		perror("Listening to socket: [FAILED]\n");
		ret = ERR_SOCKET_ACCEPT_CLIENT;
	}

	return ret;
}

void clean_socket(int *socket)
{
	close(*socket);
}

