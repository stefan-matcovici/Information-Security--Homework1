/* 
 * tcpclient.c - A simple TCP client
 * usage: tcpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "crypt-lib.c"

#define BUFSIZE 1024

unsigned char *key = (unsigned char *)"0123456789012345";

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

unsigned int create_tcp_socket(const char* serverIp, int serverPort)
{
    struct sockaddr_in  server;
    int        socketDescriptor;

    if ((socketDescriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr,"Error on creating socket: %s\n",strerror(errno));
        return -1;
    }

    server.sin_family       = AF_INET;
    server.sin_addr.s_addr  = inet_addr(serverIp);
    server.sin_port         = htons(serverPort);

    if (connect(socketDescriptor, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        fprintf(stderr,"Error connecting to server: %s\n",strerror(errno));
        return -1;
    }

    return socketDescriptor;
}

int main(int argc, char **argv) {
    int sockfd, portno, n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];

    /* check command line arguments */
    if (argc != 6) {
       fprintf(stderr,"usage: %s <hostname> <key manager port> <receviver port> <mode> <file>\n", argv[0]);
       exit(0);
    }
    
    unsigned int key_manager_socket = create_tcp_socket(argv[1], atoi(argv[2]));
    unsigned int b_socket = create_tcp_socket(argv[1], atoi(argv[3]));

    strcpy(buf, argv[4]);

    /* send the message line to the server */
    buf[3]=0;
    n = write(b_socket, buf, strlen(buf));
    if (n < 0) 
      error("ERROR writing to socket");

    strcpy(buf, argv[4]);

    /* send the message line to the server */
    buf[3]=0;
    n = write(key_manager_socket, buf, strlen(buf));
    if (n < 0) 
      error("ERROR writing to socket");

    /* print the server's reply */
    bzero(buf, BUFSIZE);
    n = read(key_manager_socket, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket");
    
    int received_key_len;
    unsigned char received_key[128];

    received_key_len = decrypt("AES-128-ECB", buf, n, key, NULL, received_key);

    printf("Key is:\n");
    BIO_dump_fp (stdout, (const char *)key, received_key_len);
    close(key_manager_socket);

    /* print the server's reply */
    bzero(buf, BUFSIZE);
    n = read(b_socket, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket");

    return 0;
}