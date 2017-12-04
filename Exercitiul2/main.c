#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void digest_message_SHA256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);
}

void digest_message_MD5(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);
}

void write_file(unsigned char* text, char* filename)
{
    FILE *f = fopen(filename, "wb");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    fprintf(f, "%s", text);

    fclose(f);
}

unsigned char* read_file(char *filename) {
    FILE *f = fopen(filename, "rt");
    assert(f);
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buffer = (unsigned char *) malloc(length + 1);
    buffer[length] = '\0';
    fread(buffer, 1, length, f);
    fclose(f);
    return buffer;
}

int main(int argc, char** argv)
{
    if ( argc != 3 )
    {
        printf("Invalid number of parameters!\n");
        exit(1);
    }
    char* file1 = argv[1];
    char* file2 = argv[2];

    unsigned char *file1_content, *file2_content;
    unsigned char *result;

    int result_len;

    file1_content = read_file(file1);
    file2_content = read_file(file2);

    digest_message_MD5(file1_content, strlen(file1_content), &result, &result_len);
    printf("%d\n", result_len);
    write_file(result, "h1_md5");

    digest_message_MD5(file2_content, strlen(file1_content), &result, &result_len);
    printf("%d\n", result_len);
    write_file(result, "h2_md5");

    return 0;
}