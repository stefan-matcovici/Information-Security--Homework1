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

unsigned int listen_socket;

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

unsigned char *key = (unsigned char *)"0123456789012345";
unsigned char *iv = (unsigned char *)"0123456789012345";

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

unsigned int accept_tcp_connection()
{
    int                 client;
    struct sockaddr_in  from;
    int                 length = sizeof(from);

    if ((client = accept(listen_socket, (struct sockaddr *)&from, (socklen_t *)&length)) < 0)
    {
        perror("Error on accept():");
        return -1;
    }

    return client;
}

int create_tcp_listening_socket(int serverPort)
{
    unsigned int        serverSocket;
    struct sockaddr_in  server;

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Error on socket():");
        return -1;
    }

    int on = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(serverPort);

    if (bind(serverSocket, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("Error on bind():");
        return -1;
    }
    
    if (listen(serverSocket, 2) == -1)
    {
        perror("Error on listen():");
        return -1;
    }

    printf("Waiting clients on port %d ...\n", serverPort);

    listen_socket = serverSocket;
    return 0;
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

    close(key_manager_socket);

    return received_key_len;
}
#endif /* !COMMUNICATION */