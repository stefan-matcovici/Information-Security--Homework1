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
  char previous_crypted_block[BUFFER_SIZE];
  char mode[4];
  int err;
  unsigned char decrypted_text[17];

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

    strncpy(mode, buf, 3);

    unsigned char received_key[128];
    int received_key_len;

    received_key_len = get_key_from_server(argv[2], argv[3], buf, received_key);

    err = send(client, "yes", 3, 0);
    if (err < 0) on_error("Client write failed\n");

    int block_size;
    r = recv(client, &block_size, sizeof(int), 0);

    memcpy(previous_crypted_block, iv, 16);
    
    while (block_size!=0)
    {
        r = recv(client, buf, block_size, 0);

        if (strcmp(mode, "ecb") == 0)
        {
            int decrypted_block_size = decrypt("AES-128-ECB", buf, block_size, received_key, NULL, decrypted_text);
            decrypted_text[decrypted_block_size] = 0;
        }
        else if (strcmp(mode, "cbc") == 0)
        {
            int decrypted_block_size = decrypt("AES-128-CBC", buf, block_size, received_key, previous_crypted_block, decrypted_text);
            decrypted_text[decrypted_block_size] = 0;
            
            memcpy(previous_crypted_block, buf, block_size);

        }

        printf("%s", decrypted_text);
        r = recv(client, &block_size, sizeof(int), 0);
    }
    printf("\n");
    fflush(stdout);
  }

  return 0;
}