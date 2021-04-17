#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"



mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;
unsigned char key[32];

char *pers = "aes generate key";
int ret;


mbedtls_entropy_init ( &entropy );

mbedtls_ctr_drbg_init ( &ctr_drbg );

if ( ( ret = mbedtls_ctr_drbg_seed ( &ctr_drbg, mbedtls_entropy_func, &entropy,
            ( unsigned char * ) pers, strlen ( pers ) ) ) != 0 )
{
    printf ( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
    goto exit;
}

if ( ( ret = mbedtls_ctr_drbg_random ( &ctr_drbg, key, 32 ) ) != 0 )
{
    printf ( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
    goto exit;
}



mbedtls_ctr_drbg_free mbedtls_entropy_free
