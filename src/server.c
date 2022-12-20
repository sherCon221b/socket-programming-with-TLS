//-------------------------------------------------------------------------
// (C) 2022 VTubongbanua
//-------------------------------------------------------------------------
//
// File Name   :   server.c
//
//-------------------------------------------------------------------------
// Function: 
//   Provides a server in socket communication with TLS
//
//-------------------------------------------------------------------------
//  Change Activities:
// tag  Reason   Ver  Rev Date      Origin          Description.
//-------------------------------------------------------------------------
// $000= ------  0.0  000 22/12/6   V.Tubongbanua   Initial Release.
//-------------------------------------------------------------------------

#include "socket_api.h"
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

#define DEBUG 0

void addClient(struct sockaddr_in *client, int socket, SSL *ssl);
void removeClient(int socket);
void showClients(SSL *ssl);
char *getName(int socket);

char *changeName(char *newName, int socket);
int isDigitStr(char *ptr);

CLIENT_ client_list[MAX_CLIENTS];
CLIENT_ getClient(int socket);

unsigned short client_count = 0;
char *commands[3] = {CMD_LIST, CMD_NAME, CMD_DEST};
struct sockaddr_in client;

//------------------------------------------------------------------------
//  Function Name	: create_server_context
//  Description		: Configures SSL context
//  Argument/s  	: void
//  Return      	: SSL_CTX *
//------------------------------------------------------------------------
SSL_CTX *create_server_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//------------------------------------------------------------------------
//  Function Name	: configure_context
//  Description		: Configures SSL context
//  Argument/s  	: SSL_CTX *ctx
//  Return      	: void
//------------------------------------------------------------------------
void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

//------------------------------------------------------------------------
//  Function Name	: addClient
//  Description		: Adds client to client list
//  Argument/s  	: struct sockaddr_in *client, int socket, SSL *ssl
//  Return      	: void
//------------------------------------------------------------------------
void addClient(struct sockaddr_in *client, int socket, SSL *ssl)
{
	client_list[client_count].address = client->sin_addr;
	client_list[client_count].port = client->sin_port;
	client_list[client_count].socket = socket;
	sprintf(client_list[client_count].name , "Socket%d", socket);
	client_list[client_count].ssl  = ssl;
	client_count++;
}

//------------------------------------------------------------------------
//  Function Name 	: removeClient
//  Description 	: Removes existing client
//  Argument/s   	: int socket
//  Return      	: void
//------------------------------------------------------------------------
void removeClient(int socket)
{
	int i=0;
	for(i=0; i<MAX_CLIENTS; i++){
		if(client_list[i].socket==socket)
		{
			int c = i;
			for ( c = i ; c < MAX_CLIENTS ; c++ )
			{
				client_list[c] = client_list[c+1];  
			}
        	break;
		}
	}
	if(client_count>0) client_count--;
	
}

//------------------------------------------------------------------------
//  Function Name 	: showClients
//  Description 	: Shows connected clients
//  Argument/s   	: SSL *ssl
//  Return      	: void
//------------------------------------------------------------------------
void showClients(SSL *ssl){
	char clientStr[MESSAGE_BUFFER];
	int i=0;
	memset(clientStr, 0, MESSAGE_BUFFER);
	SERVER_MSG(ssl,"********** Available Client/s **********\n");
	while(client_list[i].socket != '\0'){	
		sprintf(clientStr, "* %s\n*  -- Socket:%d Address: %s:%d\n",client_list[i].name, client_list[i].socket,
											inet_ntoa(client_list[i].address), 
											ntohs(client_list[i].port));
		SERVER_MSG(ssl, clientStr);
		i++;
	}
	SERVER_MSG(ssl,"****************************************\n");
	
}

//------------------------------------------------------------------------
//  Function Name 	: getName
//  Description 	: Gets the name of the client
//  Argument/s   	: char *newName, int socket
//  Return      	: char *
//------------------------------------------------------------------------
char *getName(int socket)
{
	int i;
	for (i = 0; i < MAX_CLIENTS; i++){	
		if(client_list[i].socket == socket){
			return client_list[i].name;
		}
	}
	
	return "";
}

//------------------------------------------------------------------------
//  Function Name 	: changeName
//  Description 	: Changes the name of the client
//  Argument/s   	: char *newName, int socket
//  Return      	: char *
//------------------------------------------------------------------------
char *changeName(char *newName, int socket)
{
	int i=0;

	while(client_list[i].socket!='\0')
	{	
		if(client_list[i].socket == socket){
			strcpy(client_list[i].name, newName);
			return client_list[i].name;
		}
		i++;	
	}

	return "";
}

//------------------------------------------------------------------------
//  Function Name 	: getClient
//  Description 	: Gets existing client
//  Argument/s   	: int socket
//  Return      	: CLIENT_
//------------------------------------------------------------------------
CLIENT_ getClient(int socket)
{	CLIENT_ client = {0};
	int i=0;
	for (i = 0; i < MAX_CLIENTS; i++){
		if(client_list[i].socket == socket && strlen(client_list[i].name) != 0){
			return client_list[i];
		}	
	}

	return client;
}

//------------------------------------------------------------------------
//  Function Name 	: isDigitStr
//  Description 	: Checks whether string is a digit
//  Argument/s   	: char *ptr
//  Return      	: TRUE, FALSE
//------------------------------------------------------------------------
int isDigitStr(char *ptr)
{
	while(*ptr != '\0')
	{
		if(!isdigit(*ptr)){
			return FALSE;
		}
		ptr++;
	}
	return TRUE;
}

//------------------------------------------------------------------------
//  Function Name 	: openssl_init
//  Description 	: Initialises openssl library and algorithms
//  Argument/s   	: void
//  Return      	: void
//------------------------------------------------------------------------
void openssl_init(){
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

//------------------------------------------------------------------------
//  Function Name 	: sendToAll
//  Description 	: Sends a client message to all available Client
//  Argument/s   	: char * message
//  Return      	: void
//------------------------------------------------------------------------
void sendToAll(char * message){
	int i=0;
	while(client_list[i].socket != '\0'){
		SERVER_MSG(client_list[i].ssl, message);
		i++;
	}
}

//------------------------------------------------------------------------
//  Function Name 	: messageHandler
//  Description 	: Function called after pthread to respond client messages
//  Argument/s   	: void *arg
//  Return      	: void
//------------------------------------------------------------------------
void *messageHandler (void *arg)
{	
	SSL_CTX *ctx;
	SSL *ssl;
	SOCKET *args;
	int read_size;
	int broadcast = FALSE; //default broadcast
	char client_message[MESSAGE_BUFFER]; 
	char server_message[MESSAGE_BUFFER]; 
	char *my_name;
	RET_CODE ret = OK;
	CLIENT_ destClient;

    args = (SOCKET*)arg;
	SOCKET sock = *args;
	
	memset(client_message,0, MESSAGE_BUFFER);

	ctx = create_server_context();
	configure_context(ctx);
	
	ssl= SSL_new(ctx);
	if(!ssl){
		perror("Error setting new TLS Connection!\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
		
    SSL_set_fd(ssl, sock);

	if (SSL_accept(ssl) <= OK) {
		perror("Error accepting TLS Connection!\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	addClient(&client, sock, ssl);
	
	my_name = getName(sock);
	
	//Welcome message to new client
	sprintf(server_message, "[SERVER]: Welcome %s! Type your message\n", my_name);
	SERVER_MSG(ssl, server_message);

	//Receive a message from client
	while( (read_size = SSL_read(ssl, client_message, MESSAGE_BUFFER)) > 0 )
	{		
		char *argv[MAX_CMD_INDEX] = {"server"};  //argv[0] is not an argument
		int argc;
		char opt;
		char *opts = "ln:d:";
		char *newName;
		
		int arg_index = 1;  // argument/s start at index 1
		char * pch;
		optind = 0; // start index for scanning
		opterr = 0; // disable printing if error occurs

		if(client_message[0] =='-'){
			pch = strtok(client_message," \n"); // Seperate string with space delimeter
			*(argv + arg_index) = pch;
			arg_index++;

			while (pch != NULL)
			{	
				if(arg_index > MAX_CMD_INDEX){
					ret = 1;
					break;
				}
				pch = strtok (NULL, " ");
				*(argv + arg_index) = pch;
				arg_index++;
			}
			
			if(ret!=OK){
				memset(argv, 0, MAX_CMD_INDEX);
				printf("Error: max argument reached- [%d]\n", arg_index);
				continue;
			}
			argc = arg_index - 1;

			#if DEBUG
				int i;	
				for(i=0; i< argc; i++){
					printf("index:%d, value: %s\n", i, argv[i]);
				}
			#endif

			while((opt = getopt(argc, argv, opts)) != -1)
			{ 
				memset(server_message,0, MESSAGE_BUFFER);
				switch(opt) 
				{ 
					case 'l': 
						showClients(ssl);
						break; 
					case 'n':
						newName = changeName(optarg, sock);
						sprintf(server_message, "[SERVER]: Your name was changed to %s\n", newName);
						SERVER_MSG(ssl,server_message);
						break;
					case 'd': 
						if(isDigitStr(optarg)){
							if(!(strcmp(optarg, "0"))){
								broadcast = TRUE;
								sprintf(server_message, "[SERVER]: Communication set to broadcast.\n");
							}else{
								destClient = getClient(atoi(optarg));
								if(destClient.socket){
									broadcast = FALSE;
									sprintf(server_message, "[SERVER]: You are now communicating to %s.\n", destClient.name);
								}else{
									sprintf(server_message, "[SERVER]: Invalid or unavailable client.\n");
								}
							}
						}else{
							sprintf(server_message, "[SERVER]: Option -d invalid argument. Please input valid integer\n");
						}
						SERVER_MSG(ssl,server_message);
						break; 
					case '?': 
						if (optopt == 'n' || optopt == 'd')
							sprintf(server_message, "[SERVER]: Option -%c requires an argument.\n", optopt);
						else if(isprint(optopt))
							sprintf(server_message, "[SERVER]: Unknown option `-%c'.\n", optopt);
						else
							sprintf(server_message, "[SERVER]: Unknown option character `\\x%x'.\n",optopt);
						
						SERVER_MSG(ssl,server_message);
						break;
					default:
						abort();
				} 
			} 
		}else{
			memset(server_message,0, MESSAGE_BUFFER);
			sprintf(server_message, "[%s]: %s\n", my_name, client_message);
			if(broadcast){
				sendToAll(server_message);
			}else{
				if(destClient.socket){
					SERVER_MSG(destClient.ssl,server_message);
				}else{
					SERVER_MSG(ssl,server_message);
				}
			}
		}
		
		memset(client_message, '\0', MESSAGE_BUFFER);
	}
	
	if(read_size == 0){
		removeClient(sock);
	}
	else if(read_size == -1){
		perror("recv failed\n");
	}
	
	SSL_CTX_free(ctx);
	EVP_cleanup();

	//Free the socket pointer
	free(arg);
	
	return 0;
}

int main(int argc , char *argv[])
{
	SOCKET socket_desc, new_socket;
	struct sockaddr_in server, client;
	int addr_len = sizeof(struct sockaddr_in);
	RET_CODE ret = OK;

	do{
		//Create socket
		ret = create_socket(&socket_desc);
		if (OK != ret) break;
	
		//Set the option specified
		ret = set_sock_opt(&socket_desc);
		if (OK != ret) break;

		//Prepare the sockaddr_in structure and bind
		server = get_address_to_bind_server(PORT);
		ret = bind_sock_to_address(&socket_desc, &server);
		if (OK != ret) break;
		
		//Listen
		ret = listen_to_socket(&socket_desc);
		if (OK != ret) break;

	}while(0);

	if (OK != ret){
		printf("Error socket: [%x]", ret);
		return ret;
	}

	openssl_init();

	//Accept an incoming connection
	printf("Server has been established at port %d. Waiting for incoming connections...\n", PORT);
	fflush(stdout);

	while( (new_socket = accept_client(&socket_desc, &client, &addr_len)) && (MAX_CLIENTS != client_count))
	{
		printf("Connection accepted: Socket%d\n", new_socket);
		pthread_t *handler;
		RET_CODE ret = OK;
		SOCKET *thread_args;

		thread_args = (int*) malloc(1);
		if (NULL == thread_args){
			ret = ERROR_MALLOC;
			perror("Socket pointer memory allocotion: [FAILED]\n");
			break;
		}

		*thread_args = new_socket;
	
		if (pthread_create(handler, NULL, messageHandler, (void *)thread_args) < 0){
			ret = ERROR_CREATE_THREAD;
			perror("Create connection handler: [FAILED]\n");
			break;
		}
	}
	
	if (new_socket<0)
	{
		perror("accept failed");
		exit(0);
	}
	
	return 0;
}

