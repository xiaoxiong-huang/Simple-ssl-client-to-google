#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void error(char *msg) {
    perror(msg);
    exit(0);
}

int Connect(void){
    int sock;
    struct hostent *server;
    struct sockaddr_in serveraddr;
    char hostname[20];
    int portno = 443;
    strcpy(hostname, "google.com");

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) 
        error("ERROR opening socket");

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    if (connect(sock, &serveraddr, sizeof(serveraddr)) < 0) 
      error("ERROR connecting");

    return sock;
}

SSL_CTX* InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int main(int argc, char **argv){
    SSL_CTX *ctx;
    int Server_sock;
    SSL *ssl;
    char buf[1024];
    int n;

    SSL_library_init();
    ctx = InitCTX();
    Server_sock = Connect();
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, Server_sock);

    if ( SSL_connect(ssl) == -1 ) 
        ERR_print_errors_fp(stderr);
    else{
        char *request = "GET https://www.google.com/ HTTP/1.1\r\n\r\n";
        n = SSL_write(ssl, request, strlen(request));
        if(n<0){
            printf("error sending\n");
        }
        while (n > 0)
        {
            bzero(buf, 1024);
            n = SSL_read(ssl, buf, 1000);
            printf(buf);
        }
        
    }

    return 0;
}
