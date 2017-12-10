#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "crypt-lib.c"

#include <stddef.h>

#include <errno.h>

#define BUFFER_SIZE 1024
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

unsigned char *key = (unsigned char *)"0123456789012345";

unsigned int listen_socket;

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

int main (int argc, char *argv[]) {
  unsigned int          client;
  char buf[BUFFER_SIZE];
  int err;

  if (argc != 4)
  {
    fprintf(stderr, "Usage: %s <Server Port> <hostname> <key manager port>\n", argv[0]);
    exit(1);
  }
  
  if ( create_tcp_listening_socket(atoi(argv[1])) == -1 )
    exit(1);
  
  while(1)
  {
    if ( (client = accept_tcp_connection()) == -1 )
      continue;
    
    int r = recv(client, buf, BUFFER_SIZE, 0);

    buf[3] = 0;
    if (!r) break; // done reading
    if (r < 0)on_error("Client read failed\n");

    printf("%s\n", buf);

    unsigned int key_manager_socket = create_tcp_socket(argv[2], atoi(argv[3]));
    int n = write(key_manager_socket, buf, strlen(buf));
    if (n < 0) 
      error("ERROR writing to socket");

    /* print the server's reply */
    bzero(buf, BUFFER_SIZE);
    n = read(key_manager_socket, buf, BUFFER_SIZE);
    if (n < 0) 
      error("ERROR reading from socket");
    
    int received_key_len;
    unsigned char received_key[128];

    received_key_len = decrypt("AES-128-ECB", buf, n, key, NULL, received_key);

    printf("Key is:\n");
    BIO_dump_fp (stdout, (const char *)key, received_key_len);
    close(key_manager_socket);


    err = send(client, "yes", 3, 0);
    if (err < 0) on_error("Client write failed\n");

    
  }

  return 0;
}