#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <string.h>

#include <ctype.h>

char* stoupper( char* s )
{
    char* p = s;
    while (*p = toupper( *p )) p++;
    return s;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void write_file(unsigned char* text, int length, char* filename)
{
    FILE *f = fopen(filename, "wb");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    fwrite(text, length, 1, f);

    fclose(f);
}

void read_file(char *filename, unsigned char* buffer, int* buffer_length) 
{
    FILE *f = fopen(filename, "rb");

    fseek(f, 0, SEEK_END);
    int length = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *content = (unsigned char *) malloc(length + 1);
    content[length] = '\0';
    fread(content, 1, length, f);
    
    fclose(f);

    buffer = (unsigned char *) malloc(length + 1);
    buffer = memcpy(buffer, content, length+1);
    *buffer_length = length;
}

int encrypt(const char* algorithm_name, unsigned char* plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,  unsigned char* ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *algorithm; 

    int len;

    int ciphertext_len;

    OpenSSL_add_all_algorithms();

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (!(algorithm = EVP_get_cipherbyname(algorithm_name)))
    {
        printf("Cipher name not ok\n");
        return -1;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, algorithm, NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void run_encryption(char* file1, char* file2, char* mode)
{
    unsigned char *key = (unsigned char *)"01234567890123456";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char *plaintext;
    unsigned char ciphertext[128];
    char algorithm_name[11] = "AES-128-";

    if (strcmp(mode, "ecb")==0)
    {
        iv = NULL;
    }

    int plaintext_length, ciphertext_len;

    read_file(file1, plaintext, &plaintext_length);

    strcat(algorithm_name, stoupper(mode));

    ciphertext_len = encrypt(algorithm_name, plaintext, plaintext_length, key, iv, ciphertext);
    write_file(ciphertext, ciphertext_len, "out.txt");
}

int main(int argc, char** argv)
{
    if ( argc != 4 )
    {
        printf("Invalid number of parameters!\n");
        exit(1);
    }

    char* file1 = argv[1];
    char* file2 = argv[2];
    char* mode = argv[3];

    run_encryption(file1, file2, mode);

    return 0;
}