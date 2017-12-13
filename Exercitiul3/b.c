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

void xor (unsigned char *a1, unsigned char *a2) 
{
  for (int j = 0; j < 16; j++)
  {
    a1[j] ^= a2[j];
  }
}

int main (int argc, char *argv[]) {
  unsigned int          client;
  char buf[BUFFER_SIZE];
  char previous_crypted_block[BUFFER_SIZE];
  char mode[4];
  int err;
  unsigned char decrypted_text[17];
  unsigned char received_key[17];
  int received_key_len;
  int decrypted_block_size;

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

    received_key_len = get_key_from_server(argv[2], argv[3], buf, received_key);

    err = send(client, "yes", 3, 0);
    if (err < 0) on_error("Client write failed\n");

    int block_size;
    r = recv(client, &block_size, sizeof(int), 0);

    memcpy(previous_crypted_block, iv, 16);
    
    while (block_size!=0)
    {
        r = recv(client, buf, block_size, 0);

        decrypted_block_size = decrypt("AES-128-ECB", buf, block_size, received_key, NULL, decrypted_text);


        if (strcmp(mode, "cbc") == 0)
        {
            xor(decrypted_text, previous_crypted_block);
            memcpy(previous_crypted_block, buf, block_size);
        }

        decrypted_text[decrypted_block_size] = 0;

        printf("%s", decrypted_text);
        r = recv(client, &block_size, sizeof(int), 0);
    }
    printf("\n");
    fflush(stdout);
  }

  return 0;
}