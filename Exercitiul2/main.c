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

unsigned char *hash(char *algorithm_name, const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
    const EVP_MD *algorithm; 
    EVP_MD_CTX *mdctx; 

    OpenSSL_add_all_digests();

    if (!(algorithm = EVP_get_digestbyname(algorithm_name)))
        return NULL;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, algorithm, NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(algorithm))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_destroy(mdctx);
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

unsigned char* read_file(char *filename) {
    FILE *f = fopen(filename, "rb");
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

int compare(unsigned char* hash1, unsigned char* hash2, int length)
{
    int count = 0;
    for (int i=0;i<length;i++)
    {
        if (hash1[i] == hash2[i])
        {
            count++;
        }
    }

    return count;
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
    unsigned char *result1, *result2;

    int result_len;

    file1_content = read_file(file1);
    file2_content = read_file(file2);

    hash("md5", file1_content, strlen(file1_content), &result1, &result_len);
    write_file(result1, result_len, "h1_md5");

    hash("md5", file2_content, strlen(file2_content), &result2, &result_len);
    write_file(result2, result_len, "h2_md5");

    printf("md5: %d\n", compare(result1, result2, result_len));

    hash("sha256", file1_content, strlen(file1_content), &result1, &result_len);
    write_file(result1, result_len, "h1_sha256");

    hash("sha256", file2_content, strlen(file2_content), &result2, &result_len);
    write_file(result2, result_len, "h2_sha256");

    printf("sha256: %d\n", compare(result1, result2, result_len));

    return 0;
}