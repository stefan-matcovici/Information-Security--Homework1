#ifndef COMMUNICATION
#define COMMUNICATION

#define BUFSIZE 1024

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>
#include <arpa/inet.h>

#include "crypt-lib.c"

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

unsigned char *key = (unsigned char *)"0123456789012345";

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

int get_key_from_server(char* hostname, char* port, char* mode, unsigned char* received_key)
{
    char buf[BUFSIZE];
    unsigned int key_manager_socket = create_tcp_socket(hostname, atoi(port));
    int n = write(key_manager_socket, mode, strlen(mode));
    if (n < 0) 
      error("ERROR writing to socket");

    /* print the server's reply */
    bzero(buf, BUFSIZE);
    n = read(key_manager_socket, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket");
    
    int received_key_len;

    received_key_len = decrypt("AES-128-ECB", buf, n, key, NULL, received_key);

    printf("Key is:\n");
    BIO_dump_fp (stdout, (const char *)received_key, received_key_len);
    close(key_manager_socket);

    return received_key_len;
}
#endif /* !COMMUNICATION */