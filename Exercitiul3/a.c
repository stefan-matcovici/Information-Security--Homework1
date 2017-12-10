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

#include "communication.c"

#define BUFSIZE 1024

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
    
    unsigned int b_socket = create_tcp_socket(argv[1], atoi(argv[3]));
    strcpy(buf, argv[4]);
    /* send the message line to the server */
    buf[3]=0;
    n = write(b_socket, buf, strlen(buf));
    if (n < 0) 
      error("ERROR writing to socket");

    strcpy(buf, argv[4]);
    buf[3]=0;

    unsigned char received_key[128];
    int received_key_len;

    received_key_len = get_key_from_server(argv[1], argv[2], argv[4], received_key);

    /* print the server's reply */
    bzero(buf, BUFSIZE);
    n = read(b_socket, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket)";


    return 0;
}