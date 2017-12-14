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

#include "crypt-lib.h"

unsigned int listen_socket;
unsigned char *key = (unsigned char *)"0123456789012345";
unsigned char *iv = (unsigned char *)"0123456789012345";

#endif /* !COMMUNICATION */