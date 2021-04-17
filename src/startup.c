/* ------------------------------------------------------------------
 * FxCrypt Utility - Main Source File
 * ------------------------------------------------------------------ */

#include "fxcrypt-util.h"

/**
 * Show program usage message
 */
static void show_usage ( void )
{
    fprintf ( stderr, "FxCrypt Utility - ver. " FXCRYPT_UTIL_VERSION "\n\n"
        "usage: fxcrypt command password data|input-file [-|output-file]\n\n"
        "commands:\n\n"
        "    -h  --help         Print usage message\n"
        "    -e  --encrypt      Encrypt file content\n"
        "    -d  --decrypt      Decrypt file content\n"
        "    -i  --inline       Ecnrypt data inline\n"
        "    -v  --verify       Verify file content\n\n" );
}

/**
 * Program entry point
 */
int main ( int argc, char *argv[] )
{
    int status;
    void *omem;
    size_t olen;
    const char *command;
    const char *password;
    const char *ipath;
    const char *opath;
    struct fxcrypt_context_t context;

    /* Validate arguments count */
    if ( argc < 4 )
    {
        show_usage (  );
        return 1;
    }

    /* Assign command line variables */
    command = argv[1];
    password = argv[2];
    ipath = argv[3];
    opath = argv[4];

    /* Initialize context */
    if ( fxcrypt_init ( &context, DERIVE_N_ROUNDS ) < 0 )
    {
        fprintf ( stderr, "Error: Initialization failed.\n" );
        return 1;
    }

    /* Perform operation */
    if ( !strcmp ( command, "-e" ) || !strcmp ( command, "--encrypt" ) )
    {
        if ( argc < 5 )
        {
            show_usage (  );
            status = 1;

        } else
        {
            status = fxcrypt_encrypt_file ( &context, password, ipath, opath );
        }

    } else if ( !strcmp ( command, "-i" ) || !strcmp ( command, "--inline" ) )
    {
        if ( argc < 5 )
        {
            show_usage (  );
            status = 1;

        } else
        {
            status = fxcrypt_encrypt_mem ( &context, password, ipath, strlen ( ipath ), opath );
        }

    } else if ( !strcmp ( command, "-d" ) || !strcmp ( command, "--decrypt" ) )
    {
        if ( argc < 5 )
        {
            show_usage (  );
            status = 1;

        } else if ( !strcmp ( opath, "-" ) )
        {
            status = fxcrypt_decrypt_mem ( &context, password, ipath, &omem, &olen );

            fwrite ( omem, 1, olen, stdout );
            fflush ( stdout );
            memset ( omem, '\0', olen );
            free ( omem );

        } else
        {
            status = fxcrypt_decrypt_file ( &context, password, ipath, opath );
        }

    } else if ( !strcmp ( command, "-v" ) || !strcmp ( command, "--verify" ) )
    {
        if ( ( status = fxcrypt_verify_file ( &context, password, ipath ) ) >= 0 )
        {
            printf ( "checksum is correct.\n" );
        }

    } else
    {
        show_usage (  );
        status = 1;
    }

    /* Uninitialize context */
    fxcrypt_free ( &context );

    /* Check if an error occurred */
    if ( status < 0 )
    {
        fprintf ( stderr, "Error: Operation failed.\n" );
    }

    return status;
}
