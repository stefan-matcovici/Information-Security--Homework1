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
  ERR_load_crypto_strings();
  ERR_print_errors_fp(stderr);
  abort();
}

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

int main(int argc, char** argv)
{
    char* file1 = argv[1];
    char* file2 = argv[2];
    char* mode = argv[3];

    int computed_plaintext_len;
    unsigned char computed_plaintext[256];
    unsigned char *iv = (unsigned char *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    char algorithm_name[11] = "AES-128-";
    int word_dict_len, plaintext_len, cryptotext_len;

    unsigned char* words = read_file("word_dict.txt", &word_dict_len);
    unsigned char* plaintext = read_file(file1, &plaintext_len);
    unsigned char* cryptotext = read_file(file2, &cryptotext_len);

    char* token;
    unsigned char word[17];
    int tries = 0;

    if ( argc != 4 )
    {
        printf("usage: %s <plaintext file> <cryptotext file> <mode>\n", argv[0]);
        exit(1);
    }

    if (strcmp(mode, "ecb")==0)
    {
        iv = NULL;
    }
    strcat(algorithm_name, stoupper(mode));

    token = strtok (words,"\n");
    int ok = 0;
    while (token != NULL)
    {
        tries++;
        memset(word, 0, 16);
        strcpy(word, token);
        if (strlen(word)<16)
        {
            for (int j=0;j<16;j++)
            {
                if (word[j]==0)
                {
                  word[j]=' ';
                }
            }
        }
        word[16]=0;

        computed_plaintext_len = encrypt(algorithm_name, plaintext, plaintext_len, word, iv, computed_plaintext);
        computed_plaintext[computed_plaintext_len]=0;

        if (strcmp(computed_plaintext, cryptotext)==0)
        {
            printf("Key is %s\nTried: %d\n",token,tries);
            ok = 1;
            break;
        }

        token = strtok (NULL, "\n");
    }

    if (ok == 0) 
    {
        printf("Couldn't find key\n");
    }

    return 0;
}