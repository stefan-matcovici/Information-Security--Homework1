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

    printf("%s\n", block);
    if (strcmp("ecb", mode)==0)
    {
      crypted_block_len = encrypt("AES-128-ECB", block, strlen((char*)block), received_key, NULL,  crypted_block);
    }
    else if(strcmp("cbc", mode)==0)
    {

    }

    unsigned char decrypted_text[256];
    int decrypted_block_size = decrypt("AES-128-ECB", crypted_block, crypted_block_len, received_key, NULL, decrypted_text);
    printf("Crypted %d is:\n", crypted_block_len);
    BIO_dump_fp (stdout, (const char *)crypted_block, crypted_block_len);

    printf("Key %d is:\n", 16);
    BIO_dump_fp (stdout, (const char *)received_key, 16);

    n = write(socket, &crypted_block_len, sizeof(int));
    n = write(socket, crypted_block, crypted_block_len);
    if (n < 0) 
      error("ERROR writing to socket");
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
      error("ERROR reading from socket");
    
    send_file(argv[5], argv[4], b_socket, received_key);

    return 0;
}