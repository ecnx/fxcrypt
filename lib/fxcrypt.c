/* ------------------------------------------------------------------
 * FxCrypt - Library Source
 * ------------------------------------------------------------------ */

#include "fxcrypt.h"

/**
 * Initialize FxCrypt random generator wrapper
 */
int fxcrypt_random_init ( struct fxcrypt_random_t *random )
{
    random->initialized = FALSE;
    mbedtls_entropy_init ( &random->entropy );
    mbedtls_ctr_drbg_init ( &random->ctr_drbg );

    if ( mbedtls_ctr_drbg_seed ( &random->ctr_drbg, mbedtls_entropy_func, &random->entropy,
            ( unsigned char * ) PERS_STRING, strlen ( PERS_STRING ) ) != 0 )
    {
        mbedtls_ctr_drbg_free ( &random->ctr_drbg );
        mbedtls_entropy_free ( &random->entropy );
        return -1;
    }

    random->initialized = TRUE;
    return 0;
}

/**
 * Generate random bytes with FxCrypt random generator wrapper
 */
int fxcrypt_random_bytes ( struct fxcrypt_random_t *random, uint8_t * buf, size_t len )
{
    if ( !random->initialized )
    {
        return -1;
    }

    if ( mbedtls_ctr_drbg_random ( &random->ctr_drbg, buf, len ) != 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Uninitialize FxCrypt random generator wrapper
 */
void fxcrypt_random_free ( struct fxcrypt_random_t *random )
{
    if ( random->initialized )
    {
        mbedtls_ctr_drbg_free ( &random->ctr_drbg );
        mbedtls_entropy_free ( &random->entropy );
        random->initialized = FALSE;
    }
}

/**
 * Initialize FxCrypt context
 */
int fxcrypt_init ( struct fxcrypt_context_t *context, int derive_n_rounds )
{
    context->initialized = FALSE;
    context->derive_n_rounds = derive_n_rounds;

    if ( fxcrypt_random_init ( &context->random ) < 0 )
    {
        return -1;
    }

    context->initialized = TRUE;
    return 0;
}

/**
 * Uninitialize FxCrypt context
 */
void fxcrypt_free ( struct fxcrypt_context_t *context )
{
    if ( context->initialized )
    {
        fxcrypt_random_free ( &context->random );
        context->initialized = FALSE;
    }
}

/**
 * Deriver encryption key
 */
static int pbkdf2_sha256_derive_key ( struct fxcrypt_context_t *context, const char *password,
    const uint8_t * salt, size_t salt_len, uint8_t * key, size_t key_size )
{
    mbedtls_md_context_t sha256_ctx;
    const mbedtls_md_info_t *sha256_info;

    mbedtls_md_init ( &sha256_ctx );

    if ( !( sha256_info = mbedtls_md_info_from_type ( MBEDTLS_MD_SHA256 ) ) )
    {
        mbedtls_md_free ( &sha256_ctx );
        return -1;
    }

    if ( mbedtls_md_setup ( &sha256_ctx, sha256_info, TRUE ) != 0 )
    {
        mbedtls_md_free ( &sha256_ctx );
        return -1;
    }

    if ( mbedtls_pkcs5_pbkdf2_hmac ( &sha256_ctx, ( const uint8_t * ) password,
            strlen ( password ), salt, salt_len, context->derive_n_rounds, key_size, key ) != 0 )
    {
        memset ( key, '\0', key_size );
        mbedtls_md_free ( &sha256_ctx );
        return -1;
    }

    mbedtls_md_free ( &sha256_ctx );
    return 0;
}

/**
 * Read complete block of data from file
 */
static int read_complete ( int fd, uint8_t * arr, size_t len )
{
    size_t ret;
    size_t sum;

    for ( sum = 0; sum < len; sum += ret )
    {
        if ( ( ssize_t ) ( ret = read ( fd, arr + sum, len - sum ) ) <= 0 )
        {
            return -1;
        }
    }

    return 0;
}

/**
 * Write complete block of data to file 
 */
static int write_complete ( int fd, const uint8_t * arr, size_t len )
{
    size_t ret;
    size_t sum;

    for ( sum = 0; sum < len; sum += ret )
    {
        if ( ( ssize_t ) ( ret = write ( fd, arr + sum, len - sum ) ) <= 0 )
        {
            return -1;
        }
    }

    return 0;
}

/**
 * Write complete block of data to file and mac
 */
static int write_complete_and_mac ( int fd, const uint8_t * arr, size_t len,
    mbedtls_md_context_t * md )
{
    if ( write_complete ( fd, arr, len ) < 0 )
    {
        return -1;
    }

    if ( mbedtls_md_hmac_update ( md, arr, len ) != 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Encrypt data internal
 */
static int fxcrypt_encrypt_in ( struct fxcrypt_context_t *context, const char *password,
    int ifd, int ofd, const uint8_t * imem, size_t ilen )
{
    int finish = FALSE;
    ssize_t len;
    ssize_t pos = 0;
    ssize_t left = 0;
    size_t offset = 0;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_context_t md;
    mbedtls_aes_context aes;
    uint8_t salt[AES256_KEYLEN];
    uint8_t key[AES256_KEYLEN];
    uint8_t iv[AES256_BLOCKLEN];
    uint8_t pad[AES256_BLOCKLEN];
    uint8_t hmac[SHA256_BLOCKLEN];
    uint8_t arr[FS_BLOCKLEN];

    /* Initialize stuff */
    mbedtls_md_init ( &md );
    mbedtls_aes_init ( &aes );

    /* Generate random salt and iv */
    if ( fxcrypt_random_bytes ( &context->random, salt, sizeof ( salt ) )
        || fxcrypt_random_bytes ( &context->random, iv, sizeof ( iv ) ) < 0 )
    {
        return -1;
    }

    /* Derive encryption key */
    if ( pbkdf2_sha256_derive_key ( context, password, salt, sizeof ( salt ), key,
            sizeof ( key ) ) < 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        return -1;
    }

    /* Setup HMAC context */
    if ( mbedtls_md_setup ( &md, mbedtls_md_info_from_type ( md_type ), TRUE ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Use encryption key for HMAC */
    if ( mbedtls_md_hmac_starts ( &md, key, sizeof ( key ) ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Setup AES context */
    if ( mbedtls_aes_setkey_enc ( &aes, key, AES256_KEYLEN_BITS ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Erase encryption key buffer */
    memset ( key, '\0', sizeof ( key ) );

    /* Append salt to file */
    if ( write_complete_and_mac ( ofd, salt, sizeof ( salt ), &md ) < 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Append iv to file */
    if ( write_complete_and_mac ( ofd, iv, sizeof ( iv ), &md ) < 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Encrypt file or memory content */
    if ( imem )
    {
        while ( offset < ilen )
        {
            len = ilen - offset;
            if ( len > ( ssize_t ) sizeof ( arr ) )
            {
                len = sizeof ( arr );
            }
            memcpy ( arr, imem + offset, len );
            offset += len;

            /* Stop once block of data is not aligned to AES block */
            if ( finish )
            {
                return -1;
            }

            /* Leave incomplete AES block for padding */
            if ( ( left = len % AES256_BLOCKLEN ) )
            {
                len -= left;
                pos = len;
                finish = TRUE;
            }

            if ( len )
            {
                /* Encrypt block of plaintext */
                if ( mbedtls_aes_crypt_cbc ( &aes, MBEDTLS_AES_ENCRYPT, len, iv, arr, arr ) != 0 )
                {
                    mbedtls_md_free ( &md );
                    mbedtls_aes_free ( &aes );
                    memset ( arr, '\0', sizeof ( arr ) );
                    return -1;
                }

                /* Append block of ciphertext to file */
                if ( write_complete_and_mac ( ofd, arr, len, &md ) < 0 )
                {
                    mbedtls_md_free ( &md );
                    mbedtls_aes_free ( &aes );
                    memset ( arr, '\0', sizeof ( arr ) );
                    return -1;
                }
            }
        }

    } else
    {
        while ( ( len = read ( ifd, arr, sizeof ( arr ) ) ) > 0 )
        {
            /* Stop once block of data is not aligned to AES block */
            if ( finish )
            {
                return -1;
            }

            /* Leave incomplete AES block for padding */
            if ( ( left = len % AES256_BLOCKLEN ) )
            {
                len -= left;
                pos = len;
                finish = TRUE;
            }

            if ( len )
            {
                /* Encrypt block of plaintext */
                if ( mbedtls_aes_crypt_cbc ( &aes, MBEDTLS_AES_ENCRYPT, len, iv, arr, arr ) != 0 )
                {
                    mbedtls_md_free ( &md );
                    mbedtls_aes_free ( &aes );
                    memset ( arr, '\0', sizeof ( arr ) );
                    return -1;
                }

                /* Append block of ciphertext to file */
                if ( write_complete_and_mac ( ofd, arr, len, &md ) < 0 )
                {
                    mbedtls_md_free ( &md );
                    mbedtls_aes_free ( &aes );
                    memset ( arr, '\0', sizeof ( arr ) );
                    return -1;
                }
            }
        }

        /* Check for reading error */
        if ( len < 0 )
        {
            mbedtls_md_free ( &md );
            mbedtls_aes_free ( &aes );
            memset ( arr, '\0', sizeof ( arr ) );
            return -1;
        }
    }

    /* Handle content PKCS#7 padding */
    if ( left )
    {
        memcpy ( pad, arr + pos, left );
        memset ( pad + left, AES256_BLOCKLEN - left, sizeof ( pad ) - left );

    } else
    {
        memset ( pad, AES256_BLOCKLEN, sizeof ( pad ) );
    }

    /* Erase data buffer */
    memset ( arr, '\0', sizeof ( arr ) );

    /* Encrypt padding block */
    if ( mbedtls_aes_crypt_cbc ( &aes, MBEDTLS_AES_ENCRYPT, sizeof ( pad ), iv, pad, pad ) != 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        memset ( pad, '\0', sizeof ( pad ) );
        return -1;
    }

    /* Uninitialize AES context */
    mbedtls_aes_free ( &aes );

    /* Append padding block to file */
    if ( write_complete_and_mac ( ofd, pad, sizeof ( pad ), &md ) < 0 )
    {
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Finalize HMAC */
    if ( mbedtls_md_hmac_finish ( &md, hmac ) != 0 )
    {
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Append HMAC to file */
    if ( write_complete ( ofd, hmac, sizeof ( hmac ) ) < 0 )
    {
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Uninitialize HMAC context */
    mbedtls_md_free ( &md );

    return 0;
}

/**
 * Encrypt file content
 */
int fxcrypt_encrypt_file ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath, const char *opath )
{
    int ret;
    int ifd;
    int ofd;

    /* Context must be initialized */
    if ( !context->initialized )
    {
        return -1;
    }

    /* Open input file for reading */
    if ( ( ifd = open ( ipath, O_RDONLY ) ) < 0 )
    {
        return -1;
    }

    /* Open output file for writing */
    if ( ( ofd = open ( opath, O_CREAT | O_TRUNC | O_WRONLY, 0644 ) ) < 0 )
    {
        close ( ifd );
        return -1;
    }

    /* Encrypt the file */
    ret = fxcrypt_encrypt_in ( context, password, ifd, ofd, NULL, 0 );

    /* Clenaup */
    syncfs ( ofd );
    close ( ifd );
    close ( ofd );

    return ret;
}

/**
 * Encrypt file content
 */
int fxcrypt_encrypt_mem ( struct fxcrypt_context_t *context, const char *password,
    const void *imem, size_t ilen, const char *opath )
{
    int ret;
    int ofd;

    /* Context must be initialized */
    if ( !context->initialized )
    {
        return -1;
    }

    /* Open output file for writing */
    if ( ( ofd = open ( opath, O_CREAT | O_TRUNC | O_WRONLY, 0644 ) ) < 0 )
    {
        return -1;
    }

    /* Encrypt the file */
    ret = fxcrypt_encrypt_in ( context, password, -1, ofd, ( const uint8_t * ) imem, ilen );

    /* Clenaup */
    syncfs ( ofd );
    close ( ofd );

    return ret;
}

/**
 * Get unaligned data length from PKCS#7 padding block
 */
static int pkcs7_get_unaligned_length ( const uint8_t * arr, ssize_t len, ssize_t * result )
{
    ssize_t i;
    uint8_t padlen;

    if ( len > 256 || ( padlen = arr[len - 1] ) > len )
    {
        return -1;
    }

    for ( i = len - padlen; i + 1 < len; i++ )
    {
        if ( arr[i] != padlen )
        {
            return -1;
        }
    }

    *result = len - padlen;
    return 0;
}

/**
 * Decrypt data internal
 */
static int fxcrypt_decrypt_in ( struct fxcrypt_context_t *context, const char *password,
    int ifd, int ofd, uint8_t * omem, size_t *olen )
{
    ssize_t len;
    ssize_t left;
    size_t limit = 0;
    size_t offset;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_context_t md;
    mbedtls_aes_context aes;
    uint8_t salt[AES256_KEYLEN];
    uint8_t key[AES256_KEYLEN];
    uint8_t iv[AES256_BLOCKLEN];
    uint8_t hmac[SHA256_BLOCKLEN];
    union
    {
        struct
        {
            uint8_t pad[AES256_BLOCKLEN];
            uint8_t hmac[SHA256_BLOCKLEN];
        } s;
        uint8_t bytes[AES256_BLOCKLEN + SHA256_BLOCKLEN];
    } tail;
    uint8_t arr[FS_BLOCKLEN];

    /* Initialize stuff */
    mbedtls_md_init ( &md );
    mbedtls_aes_init ( &aes );

    /* Setup decrypt to memory variables */
    if ( omem && olen )
    {
        offset = 0;
        limit = *olen;
    }

    /* Read salt from file */
    if ( read_complete ( ifd, salt, sizeof ( salt ) ) < 0 )
    {
        return -1;
    }

    /* Read iv from file */
    if ( read_complete ( ifd, iv, sizeof ( iv ) ) < 0 )
    {
        return -1;
    }

    /* Derive encryption key */
    if ( pbkdf2_sha256_derive_key ( context, password, salt, sizeof ( salt ), key,
            sizeof ( key ) ) < 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        return -1;
    }

    /* Setup HMAC context */
    if ( mbedtls_md_setup ( &md, mbedtls_md_info_from_type ( md_type ), TRUE ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Use encryption key for HMAC */
    if ( mbedtls_md_hmac_starts ( &md, key, sizeof ( key ) ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Update HMAC with salt */
    if ( mbedtls_md_hmac_update ( &md, salt, sizeof ( salt ) ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Update HMAC with iv */
    if ( mbedtls_md_hmac_update ( &md, iv, sizeof ( iv ) ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Setup AES context */
    if ( mbedtls_aes_setkey_dec ( &aes, key, AES256_KEYLEN_BITS ) != 0 )
    {
        memset ( key, '\0', sizeof ( key ) );
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Erase encryption key buffer */
    memset ( key, '\0', sizeof ( key ) );

    /* Read first chunk of data */
    if ( read_complete ( ifd, tail.bytes, sizeof ( tail.bytes ) ) < 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Encrypt file content */
    while ( ( len =
            read ( ifd, arr + sizeof ( tail.bytes ),
                sizeof ( arr ) - sizeof ( tail.bytes ) ) ) > 0 )
    {
        /* Reuse last chunk as first chunk */
        memcpy ( arr, tail.bytes, sizeof ( tail.bytes ) );

        /* Use last chunk as first chunk */
        memcpy ( tail.bytes, arr + len, sizeof ( tail.bytes ) );

        /* Block of data must be aligned to AES block */
        if ( len % AES256_BLOCKLEN )
        {
            mbedtls_md_free ( &md );
            mbedtls_aes_free ( &aes );
            memset ( arr, '\0', sizeof ( arr ) );
            return -1;
        }

        /* Update HMAC with read data */
        if ( mbedtls_md_hmac_update ( &md, arr, len ) != 0 )
        {
            mbedtls_md_free ( &md );
            mbedtls_aes_free ( &aes );
            memset ( arr, '\0', sizeof ( arr ) );
            return -1;
        }

        /* Encrypt block of plaintext */
        if ( mbedtls_aes_crypt_cbc ( &aes, MBEDTLS_AES_DECRYPT, len, iv, arr, arr ) != 0 )
        {
            mbedtls_md_free ( &md );
            mbedtls_aes_free ( &aes );
            memset ( arr, '\0', sizeof ( arr ) );
            return -1;
        }

        /* Append block of plaintext to memory or file */
        if ( omem && olen )
        {
            if ( offset + len >= limit )
            {
                mbedtls_md_free ( &md );
                mbedtls_aes_free ( &aes );
                memset ( arr, '\0', sizeof ( arr ) );
                return -1;
            }

            memcpy ( omem + offset, arr, len );
            offset += len;

        } else if ( ofd >= 0 )
        {
            if ( write_complete ( ofd, arr, len ) < 0 )
            {
                mbedtls_md_free ( &md );
                mbedtls_aes_free ( &aes );
                memset ( arr, '\0', sizeof ( arr ) );
                return -1;
            }
        }
    }

    /* Check for reading error */
    if ( len < 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        memset ( arr, '\0', sizeof ( arr ) );
        return -1;
    }

    /* Erase data buffer */
    memset ( arr, '\0', sizeof ( arr ) );

    /* Extra data here are forbidden */
    if ( len )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Update HMAC with read data */
    if ( mbedtls_md_hmac_update ( &md, tail.s.pad, sizeof ( tail.s.pad ) ) != 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        return -1;
    }

    /* Decrypt padding block */
    if ( mbedtls_aes_crypt_cbc ( &aes, MBEDTLS_AES_DECRYPT, sizeof ( tail.s.pad ), iv, tail.s.pad,
            tail.s.pad ) != 0 )
    {
        mbedtls_md_free ( &md );
        mbedtls_aes_free ( &aes );
        memset ( tail.s.pad, '\0', sizeof ( tail.s.pad ) );
        return -1;
    }

    /* Uninitialize AES context */
    mbedtls_aes_free ( &aes );

    /* Get padding length */
    if ( pkcs7_get_unaligned_length ( tail.s.pad, sizeof ( tail.s.pad ), &left ) < 0 )
    {
        mbedtls_md_free ( &md );
        memset ( tail.s.pad, '\0', sizeof ( tail.s.pad ) );
        return -1;
    }

    /* Append block of plaintext to memory or file */
    if ( omem && olen )
    {
        if ( offset + left >= limit )
        {
            mbedtls_md_free ( &md );
            memset ( tail.s.pad, '\0', sizeof ( tail.s.pad ) );
            return -1;
        }

        memcpy ( omem + offset, tail.s.pad, left );
        offset += left;

    } else if ( ofd >= 0 )
    {
        if ( write_complete ( ofd, tail.s.pad, left ) < 0 )
        {
            mbedtls_md_free ( &md );
            memset ( tail.s.pad, '\0', sizeof ( tail.s.pad ) );
            return -1;
        }
    }

    /* Finalize HMAC */
    if ( mbedtls_md_hmac_finish ( &md, hmac ) != 0 )
    {
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Verify HMAC */
    if ( memcmp ( hmac, tail.s.hmac, sizeof ( hmac ) ) < 0 )
    {
        mbedtls_md_free ( &md );
        return -1;
    }

    /* Uninitialize HMAC context */
    mbedtls_md_free ( &md );

    /* Uodate decrypt to memory variables */
    if ( omem && olen )
    {
        *olen = offset;
    }

    return 0;
}

/**
 * Decrypt file content
 */
int fxcrypt_decrypt_file ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath, const char *opath )
{
    int ret;
    int ifd;
    int ofd;

    /* Context must be initialized */
    if ( !context->initialized )
    {
        return -1;
    }

    /* Open input file for reading */
    if ( ( ifd = open ( ipath, O_RDONLY ) ) < 0 )
    {
        return -1;
    }

    /* Open output file for writing */
    if ( ( ofd = open ( opath, O_CREAT | O_TRUNC | O_WRONLY, 0644 ) ) < 0 )
    {
        close ( ifd );
        return -1;
    }

    /* Encrypt the file */
    ret = fxcrypt_decrypt_in ( context, password, ifd, ofd, NULL, NULL );

    /* Clenaup */
    syncfs ( ofd );
    close ( ifd );
    close ( ofd );

    return ret;
}

/**
 * Decrypt file content into memory
 */
int fxcrypt_decrypt_mem ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath, void **omem, size_t *olen )
{
    int ret;
    int ifd;
    uint8_t *local_omem;
    size_t local_olen;

    /* Context must be initialized */
    if ( !context->initialized )
    {
        return -1;
    }

    /* Open input file for reading */
    if ( ( ifd = open ( ipath, O_RDONLY ) ) < 0 )
    {
        return -1;
    }

    /* Measure input file */
    if ( ( ssize_t ) ( local_olen = ( size_t ) lseek ( ifd, 0, SEEK_END ) ) < 0 )
    {
        close ( ifd );
        return -1;
    }

    /* Restore file pointer */
    if ( lseek ( ifd, 0, SEEK_SET ) < 0 )
    {
        close ( ifd );
        return -1;
    }

    /* Allocate output buffer */
    if ( !( local_omem = ( uint8_t * ) malloc ( local_olen ) ) )
    {
        close ( ifd );
        return -1;
    }

    /* Encrypt the file */
    if ( ( ret = fxcrypt_decrypt_in ( context, password, ifd, -1, local_omem, &local_olen ) ) >= 0 )
    {
        *omem = local_omem;
        *olen = local_olen;
    }

    /* Clenaup */
    close ( ifd );

    return ret;
}

/**
 * Verify file content
 */
int fxcrypt_verify_file ( struct fxcrypt_context_t *context, const char *password,
    const char *ipath )
{
    int ret;
    int ifd;

    /* Context must be initialized */
    if ( !context->initialized )
    {
        return -1;
    }

    /* Open input file for reading */
    if ( ( ifd = open ( ipath, O_RDONLY ) ) < 0 )
    {
        return -1;
    }

    /* Encrypt the file */
    ret = fxcrypt_decrypt_in ( context, password, ifd, -1, NULL, NULL );

    /* Clenaup */
    close ( ifd );

    return ret;
}
