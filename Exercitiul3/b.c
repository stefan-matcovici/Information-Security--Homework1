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


#include "communication.c"

#include <stddef.h>

#include <errno.h>

#define BUFFER_SIZE 1024
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

unsigned int listen_socket;

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
    fprintf(stderr, "Usage: %s <server Port> <hostname> <key manager port>\n", argv[0]);
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

    unsigned char received_key[128];
    int received_key_len;

    received_key_len = get_key_from_server(argv[2], argv[3], buf, received_key);

    err = send(client, "yes", 3, 0);
    if (err < 0) on_error("Client write failed\n");
    
  }

  return 0;
}