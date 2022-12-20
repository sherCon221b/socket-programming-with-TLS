//-------------------------------------------------------------------------
// (C) 2022 VTubongbanua
//-------------------------------------------------------------------------
//
// File Name   :   socket_api.h
// Class Name  :   
// Stereotype  :   
//
//-------------------------------------------------------------------------
// Function: 
//   Provide api to use socket standard library
//
//-------------------------------------------------------------------------
//  Change Activities:
// tag  Reason   Ver  Rev Date      Origin          Description.
//-------------------------------------------------------------------------
// $000= ------  0.0  000 22/12/6   V.Tubongbanua   Initial Release.
//-------------------------------------------------------------------------

#ifndef _SOCKET_API_H_
#define _SOCKET_API_H_

#include <stdio.h>	//printf
#include <string.h>	//strlen
#include <stdlib.h>	//strlen
#include <sys/socket.h>	//socket
#include <arpa/inet.h>	//inet_addr
#include <unistd.h>

#include <pthread.h> //for threading , link with lpthread

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 443

#define TRUE 1
#define FALSE 0
#define INVALID_INDEX -1
#define MAX_CLIENTS 10


#define BACKLOG 3
#define EQUAL_STRING 0
#define MESSAGE_BUFFER 2000

#define SERVER_MSG(ssl,message) SSL_write(ssl , message, strlen(message)) 

#define CMD_LIST "-list"
#define CMD_NAME "-name"
#define CMD_DEST "-dest"
#define MAX_CMD_INDEX 7

#define ARG_BROADCAST "all"

typedef int SOCKET;

typedef enum {
    FAIL = -1,
    OK = 0,
    ERR_SOCKET_CREATE,
    ERR_SOCKET_CONNECT,
    ERR_SOCKET_SET_OPT,
    ERR_SOCKET_BIND_TO_ADDR,
    ERR_SOCKET_LISTEN,
    ERR_SOCKET_ACCEPT_CLIENT,
    ERROR_MALLOC,
    ERROR_CREATE_THREAD,
}RET_CODE;

typedef struct CLIENT{
	unsigned short socket;
	struct in_addr address;
	unsigned short port;
	char name[20];
    SSL *ssl;
}CLIENT_;

// Client
RET_CODE connect_sock_to_address(SOCKET *sock_desc, struct sockaddr_in *addr);


// Server
RET_CODE set_sock_opt(SOCKET *socket);
RET_CODE bind_sock_to_address(SOCKET *socket, struct sockaddr_in *addr);
RET_CODE listen_to_socket(SOCKET *socket);
RET_CODE accept_client(SOCKET *socket, struct sockaddr_in *client, int *addr_len);

// Common
RET_CODE create_socket(SOCKET *sock_desc);
struct sockaddr_in get_address_to_bind_server(int port);
void clean_socket(SOCKET *socket);

#endif // _SOCKET_API_H_

