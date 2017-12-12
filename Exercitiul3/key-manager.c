#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

#include "crypt-lib.c"

#include <stddef.h>

#include <errno.h>

#define BUFFER_SIZE 1024
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

unsigned char *ecb_key = (unsigned char *)"1234501234567890";
unsigned char *cbc_key = (unsigned char *)"9012345012345678";
unsigned char *key = (unsigned char *)"0123456789012345";

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

unsigned char *get_key(char* mode)
{
    if (strcmp(mode, "cbc") == 0)
    {
        return cbc_key;
    }
    else if (strcmp(mode, "ecb") == 0)
    {
        return ecb_key;
    }

    return NULL;
}

int main (int argc, char *argv[]) {
  unsigned int          client;
  char buf[BUFFER_SIZE];
  int err;

  if (argc < 2)
  {
    fprintf(stderr, "Usage: %s <Server Port> [-v]\n", argv[0]);
    exit(1);
  }

  if (argc == 3)
  {
      if (strcmp(argv[2], "-v")==0)
        set_verbose();
  }
  
  if ( create_tcp_listening_socket(atoi(argv[1])) == -1 )
    exit(1);
  
  while(1)
  {
    if ( (client = accept_tcp_connection()) == -1 )
      continue;
    
    int read = recv(client, buf, BUFFER_SIZE, 0);
    buf[3] = 0;
    message_log("Received message: ", buf);

    unsigned char* selected_key = get_key(buf);
    unsigned char crypted_key[128];

    if (selected_key==NULL)
    {
        printf("Incorrect mode: %s\n", buf);
        exit(1);
    }

    int crypted_key_len;
    crypted_key_len = encrypt("AES-128-ECB", selected_key, strlen((char *)selected_key), key, NULL, crypted_key);

    binary_log("Sending back crypted key", crypted_key, crypted_key_len);

    err = send(client, crypted_key, crypted_key_len, 0);
    if (err < 0) on_error("Client write failed\n");
  }

  return 0;
}