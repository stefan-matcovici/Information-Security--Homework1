#ifndef CRYPTLIB
#define CRYPTLIB

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int verbose = 0;

void set_verbose();
void handleErrors(void);
int encrypt(const char* algorithm_name, unsigned char* plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,  unsigned char* ciphertext);
int decrypt(const char* algorithm_name, unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void binary_log(const char* message, unsigned char* content, int len);
void message_log(char* message, char* content);

#endif /* !CRYPTLIB */