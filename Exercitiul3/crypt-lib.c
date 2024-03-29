#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int verbose = 0;

void set_verbose()
{
    verbose = 1;
}

void handleErrors(void)
{
  ERR_load_crypto_strings();
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(const char* algorithm_name, unsigned char* plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,  unsigned char* ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *algorithm; 

    int len;

    int ciphertext_len;

    OpenSSL_add_all_algorithms();

    // printf("Key %d is:\n", strlen((char*)key));
    // BIO_dump_fp (stdout, (const char *)key, strlen((char*)key));

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (!(algorithm = EVP_get_cipherbyname(algorithm_name)))
    {
        printf("Cipher name not ok\n");
        return -1;
    }

    // printf("Plaintext %d is:\n", plaintext_len);
    // BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, algorithm, NULL, key, iv))
        handleErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

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

    // printf("Ciphertext %d is:\n", ciphertext_len);
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    return ciphertext_len;
}

int decrypt(const char* algorithm_name, unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  const EVP_CIPHER *algorithm; 

  int len;

  int plaintext_len;

  OpenSSL_add_all_algorithms();

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if (!(algorithm = EVP_get_cipherbyname(algorithm_name)))
  {
      printf("Cipher name not ok\n");
      return -1;
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, algorithm, NULL, key, iv))
    handleErrors();

  EVP_CIPHER_CTX_set_padding(ctx, 0);

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void binary_log(const char* message, unsigned char* content, int len)
{
    if (verbose==1)
    {
        printf("%s of length %d:\n", message, len);
        BIO_dump_fp (stdout, (const char *)content, len);
    }
}

void message_log(char* message, char* content)
{
    if (verbose==1)
    {
        printf("%s %s\n", message, content);
    }
}