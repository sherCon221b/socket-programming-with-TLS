//-------------------------------------------------------------------------
// (C) 2022 VTubongbanua
//-------------------------------------------------------------------------
//
// File Name   :   client.c 
//
//-------------------------------------------------------------------------
// Function: 
//   Provides socket client with TLS
//
//-------------------------------------------------------------------------
// Change Activities:
// tag  Reason   Ver  Rev Date      Origin          Description.
//-------------------------------------------------------------------------
// $000= ------  0.0  000 22/12/6   V.Tubongbanua   Initial Release.
//-------------------------------------------------------------------------

#include "socket_api.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL *ssl;

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
//  Function Name	: create_client_context
//  Description		: Creates client context
//  Argument/s  	: void
//  Return      	: SSL_CTX *
//------------------------------------------------------------------------
SSL_CTX *create_client_context(){
	const SSL_METHOD *meth;
	SSL_CTX *ctx;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	if(!ctx){
		perror("unable to create new context!\n");
		ERR_print_errors_fp(stderr);
		exit(0);
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
//  Function Name	: openssl_show_certificate
//  Description		: Shows certificate's subject and issuer info
//  Argument/s  	: SSL *ssl
//  Return      	: void
//------------------------------------------------------------------------
void openssl_show_certificate(SSL *ssl){
	X509 *cert;
	char *part;

	//get server certificate
	cert = SSL_get_peer_certificate(ssl);

	if(cert != NULL){
		printf("Server side Certificate information:\n");
		part = X509_NAME_oneline(X509_get_subject_name(cert),0,0);
		printf("SUbj: %s\n", part);
			part = X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
		printf("CA: %s\n", part);
		free(part);
		X509_free(cert);
	} else {
		printf("No Certificate issued!\n");
	}
}

//------------------------------------------------------------------------
//  Function Name	: messageHandler
//  Description		: Function that handles server message.
//  Argument/s  	: void *args_ptr
//  Return      	: void
//------------------------------------------------------------------------
void *messageHandler (void *args_ptr)
{	
	int result;
	SSL_CTX *ctx;
	int read_size;
	char server_reply[MESSAGE_BUFFER] = {0}; 

	SOCKET *args;
    args = (SOCKET*) args_ptr;

	SOCKET sock = *args;

	openssl_init();

	ctx = create_client_context();
	configure_context(ctx);

	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, sock);

	result = SSL_connect(ssl);

	if(result == -1){
        ERR_print_errors_fp(stderr);
		exit(0);
    }

	//show server certificate information
	openssl_show_certificate(ssl);

	while( (read_size = SSL_read(ssl, server_reply, MESSAGE_BUFFER)) > 0 )
	{	
		printf("%s", server_reply);
		memset(server_reply, 0, MESSAGE_BUFFER);
	}

	if(read_size == 0){
		perror("Server disconnected...");	
	}
	else if(read_size == -1){
		perror("Message reception failed ...");	
	} else{}

	SSL_shutdown(ssl);
    SSL_free(ssl);
	
	//Free the socket pointer
	free(args_ptr);
	
	clean_socket(&sock);
	exit(0);
}

int main(int argc , char *argv[])
{
	char message[MESSAGE_BUFFER] ;
	struct sockaddr_in server;
	SOCKET socket_desc;
	pthread_t *handler;
	SOCKET *thread_args;

	RET_CODE ret;

	do{
		//Create socket
		ret = create_socket(&socket_desc);
		if (OK != ret) break;

		//Prepare address and connect socket to address
		server = get_address_to_bind_server(PORT);
		ret = connect_sock_to_address(&socket_desc, &server);
		if (OK != ret) break;
	
		thread_args = (SOCKET*) malloc(1);
		if (NULL == thread_args){
			ret = ERROR_MALLOC;
			perror("Socket pointer memory allocotion: [FAILED]\n");
			break;
		}

		*thread_args  = socket_desc;

		//Create connection handler
		if (pthread_create(handler, NULL, messageHandler, (void *)thread_args) < 0){
			perror("Create connection handler: [FAILED]\n");
			ret = ERROR_CREATE_THREAD;
			break;
		}

	}while(0);
	
	if (OK != ret){
		printf("Error socket: [%x]\n", ret);
		return ret;
	}

	// keep communicating with server
	while(TRUE)
	{
		//gets string input
		memset(message, 0, MESSAGE_BUFFER);

		if (fgets(message, sizeof(message), stdin) == NULL) {
			printf("Fail to read the input stream");
		}
		else {
			message[strcspn(message, "\n")] = '\0'; // removes newline
		}
		SERVER_MSG(ssl,message);
	}

	return 0;
}
