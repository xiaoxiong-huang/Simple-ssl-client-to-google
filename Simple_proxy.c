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
#include <stdlib.h>
#include <sys/types.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 1024

void error(char *msg) {
    perror(msg);
    exit(0);
}

SSL_CTX *InitCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */
    SSL_load_error_strings();         /* Bring in and register error messages */
    ctx = SSL_CTX_new(TLSv1_2_server_method());        /* Create new context */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int openConnection()
{
    int listenfd;                  /* listening socket */
    int connfd;                    /* connection socket */
    int portno;                    /* port to listen on */
    int clientlen;                 /* byte size of client's address */
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in clientaddr; /* client addr */
    struct hostent *hostp;         /* client host info */
    char buf[BUFSIZE];             /* message buffer */
    char *hostaddrp;               /* dotted decimal host addr string */
    int optval;                    /* flag value for setsockopt */
    int n;                         /* message byte size */

    /* check command line args */
    portno = 8080;

    /* socket: create a socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
        error("ERROR opening socket");

    /* setsockopt: Handy debugging trick that lets 
   * us rerun the server immediately after we kill it; 
   * otherwise we have to wait about 20 secs. 
   * Eliminates "ERROR on binding: Address already in use" error. 
   */
    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval, sizeof(int));

    /* build the server's internet address */
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;                     /* we are using the Internet */
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);      /* accept reqs to any IP addr */
    serveraddr.sin_port = htons((unsigned short)portno); /* port to listen on */

    /* bind: associate the listening socket with a port */
    if (bind(listenfd, (struct sockaddr *)&serveraddr,
             sizeof(serveraddr)) < 0)
        error("ERROR on binding");

    /* listen: make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */
        error("ERROR on listen");

    /* main loop: wait for a connection request, echo input line, 
     then close connection. */
    clientlen = sizeof(clientaddr);
    /* accept: wait for a connection request */
    connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
    if (connfd < 0)
        error("ERROR on accept");

    /* gethostbyaddr: determine who sent the message */
    hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
                          sizeof(clientaddr.sin_addr.s_addr), AF_INET);
    if (hostp == NULL)
        error("ERROR on gethostbyaddr");
    hostaddrp = inet_ntoa(clientaddr.sin_addr);
    if (hostaddrp == NULL)
        error("ERROR on inet_ntoa\n");
    printf("server established connection with %s (%s)\n",
           hostp->h_name, hostaddrp);
    return connfd;
}

void LoadCertificates(SSL_CTX* ctx, char* KeyFile, char* CertFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    printf("\n\n\n11111\n\n\n");
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    int Server_sock;
    SSL *ssl;
    char buf[BUFSIZE]; 
    int n;
    int i;

    SSL_library_init();
    ctx = InitCTX();
    LoadCertificates(ctx, "key.pem", "ca.pem");

    Server_sock = openConnection();
    /* read: read input string from the client */
    bzero(buf, BUFSIZE);
    n = read(Server_sock, buf, BUFSIZE);
    if (n < 0)
        error("ERROR reading from socket");
    printf("server received %d bytes: \n\n\n%s\n\n\n", n, buf);
    n=0;
    n = write(Server_sock, "HTTP/1.1 200 Connection Established\r\n\r\n", strlen("HTTP/1.1 200 Connection Established\r\n\r\n"));


    printf("sent %d byte to socket\n\n",n);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, Server_sock);
    if ( (i = SSL_accept(ssl)) == 0 )     /* do SSL-protocol accept */
    {
        ERR_print_errors_fp(stderr);
    }
    printf("accept: %d\n\n\n",i);

    n = 0;
    bzero(buf, BUFSIZE);
    n = SSL_read(ssl, buf, 1024);
    printf("recived from SSL: \n %d\n",n);
    ERR_print_errors_fp(stderr);
    
    n = SSL_write(ssl,"200 ok ok ok", strlen("200 ok ok ok"));
    printf("send %d byte using ssl!!!!\n",n);
    return 1;
}