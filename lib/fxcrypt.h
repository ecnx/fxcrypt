/* ------------------------------------------------------------------
 * FxCrypt - Library Source
 * ------------------------------------------------------------------ */

#ifndef FXCRYPT_LIB_H
#define FXCRYPT_LIB_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pkcs5.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define AES256_KEYLEN 32
#define AES256_KEYLEN_BITS (AES256_KEYLEN * 8)
#define AES256_BLOCKLEN 16
#define SHA256_BLOCKLEN 32
#define PERS_STRING "FxCrypt"
#define FS_BLOCKLEN 4096

/**
 * FxCrypt random generator
 */
struct fxcrypt_random_t
{
    int initialized;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
};

/**
 * FxCrypt context structure
 */
struct fxcrypt_context_t
{
    int initialized;
    int derive_n_rounds;
    struct fxcrypt_random_t random;
};

/**
 * Initialize FxCrypt random generator wrapper
 */
extern int fxcrypt_random_init ( struct fxcrypt_random_t *random );

/**
 * Generate random bytes with FxCrypt random generator wrapper
 */
extern int fxcrypt_random_bytes ( struct fxcrypt_random_t *random, uint8_t * buf, size_t len );

/**
 * Uninitialize FxCrypt random generator wrapper
 */
extern void fxcrypt_random_free ( struct fxcrypt_random_t *random );

/**
 * Initialize FxCrypt context
 */
extern int fxcrypt_init ( struct fxcrypt_context_t *context, int derive_n_rounds );

/**
 * Uninitialize FxCrypt context
 */
extern void fxcrypt_free ( struct fxcrypt_context_t *context );

/**
 * Encrypt file content
 */
extern int fxcrypt_encrypt_file ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath, const char *opath );

/**
 * Encrypt memory content to file
 */
extern int fxcrypt_encrypt_mem ( struct fxcrypt_context_t *context, const char *password,
    const void *imem, size_t ilen, const char *opath );

/**
 * Decrypt file content
 */
extern int fxcrypt_decrypt_file ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath, const char *opath );

/**
 * Decrypt file content into memory
 */
extern int fxcrypt_decrypt_mem ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath, void **omem, size_t *olen );

/**
 * Verify file content
 */
extern int fxcrypt_verify_file ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath );

#endif
