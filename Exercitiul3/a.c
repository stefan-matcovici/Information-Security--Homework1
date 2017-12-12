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
#define BLOCKSIZE 16

unsigned char* read_file(char *filename, int* buffer_length) 
{
    FILE *f = fopen(filename, "rb");

    fseek(f, 0, SEEK_END);
    int length = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *content = (unsigned char *) malloc(length + 1);
    content[length] = '\0';
    fread(content, 1, length, f);
    
    fclose(f); 

    *buffer_length = length;

    return content;
}

void send_file(char* filename, char* mode, unsigned int socket, unsigned char* received_key)
{
  int content_length, n;
  unsigned char* content = read_file(filename, &content_length);
  unsigned char block[BLOCKSIZE+1];
  unsigned char crypted_block[BLOCKSIZE];
  unsigned char previous_crypted_block[BLOCKSIZE];

  memcpy(previous_crypted_block, iv, BLOCKSIZE);

  int crypted_block_len;

  for (int i=0;i<content_length;i+=BLOCKSIZE)
  {
    strncpy(block, content+i, BLOCKSIZE);
    block[BLOCKSIZE]=0;

    if (strlen(block)!=BLOCKSIZE)
    {
      for (int j=0;j<BLOCKSIZE;j++)
      {
        if (block[j]==0)
        {
          block[j]=' ';
        }
      }
    }

    binary_log("Plaintext block ", block, strlen(block));
    if (strcmp("ecb", mode)==0)
    {
      crypted_block_len = encrypt("AES-128-ECB", block, strlen((char*)block), received_key, NULL,  crypted_block);
    }
    else if(strcmp("cbc", mode)==0)
    {
      crypted_block_len = encrypt("AES-128-CBC", block, strlen((char*)block), received_key, previous_crypted_block,  crypted_block);
    }

    unsigned char decrypted_text[256];
    int decrypted_block_size = decrypt("AES-128-ECB", crypted_block, crypted_block_len, received_key, NULL, decrypted_text);
    binary_log("Sending crypted block ", crypted_block, crypted_block_len);

    n = write(socket, &crypted_block_len, sizeof(int));
    n = write(socket, crypted_block, crypted_block_len);
    if (n < 0) 
      error("ERROR writing to socket");
    
    memcpy(previous_crypted_block, crypted_block, BLOCKSIZE);
  }

  int zero_size = 0;
  n = write(socket, &zero_size, sizeof(int));
    if (n < 0) 
      error("ERROR writing to socket");
}

int main(int argc, char **argv) {
    int sockfd, portno, n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];

    if (argc < 6) {
       fprintf(stderr,"usage: %s <hostname> <key manager port> <receviver port> <mode> <file> [-v]\n", argv[0]);
       exit(0);
    }

    if (argc == 7)
    {
        if (strcmp(argv[6], "-v")==0)
          set_verbose();
    }
    
    unsigned int b_socket = create_tcp_socket(argv[1], atoi(argv[3]));
    strcpy(buf, argv[4]);
    buf[3]=0;
    n = write(b_socket, buf, strlen(buf));
    if (n < 0) 
      error("ERROR writing to socket");

    unsigned char received_key[128];
    int received_key_len;
    received_key_len = get_key_from_server(argv[1], argv[2], argv[4], received_key);

    bzero(buf, BUFSIZE);
    n = read(b_socket, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket");
    
    send_file(argv[5], argv[4], b_socket, received_key);

    return 0;
}