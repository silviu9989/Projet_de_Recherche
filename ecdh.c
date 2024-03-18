#include "gmp.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "WJ/WjCryptLib_AesCtr.h"

#define NB_KEYS 10 //number of keys to compute: TO CHANGE IF NEED BE

void add_point(mpz_t Sumx, mpz_t Sumy, mpz_t P1x, mpz_t P1y, mpz_t P2x, mpz_t P2y, mpz_t modulo_base)
{
    mpz_t m, doi_in_mpz, aux1, aux2, aux3, P1xaux; mpz_inits(m, doi_in_mpz, aux1, aux2, aux3, P1xaux, NULL);
    mpz_set_ui (doi_in_mpz, 2);
    mpz_set(P1xaux, P1x);

    if(( mpz_cmp(P1x, P2x) == 0 ) && ( mpz_cmp(P1y, P2y) == 0 ))
        {
            mpz_mul(aux1, P1x, P1x);
            mpz_mul_ui(aux1, aux1, 3);
            mpz_sub_ui(aux1, aux1, 3);
            mpz_invert(aux2, doi_in_mpz, modulo_base);
            mpz_invert(aux3, P1y, modulo_base);
            mpz_mul(m, aux1, aux2);
            mpz_mul(m, m, aux3);
            mpz_mod(m, m, modulo_base);
        }
        else {
            mpz_sub(aux1, P2y, P1y);
            mpz_sub(aux2, P2x, P1x);
            mpz_invert(aux2, aux2, modulo_base);
            mpz_mul(aux1, aux1, aux2);
            mpz_mod(m, aux1, modulo_base);
        }

        mpz_add(aux1, P1x, P2x);
        mpz_mul_si(aux1, aux1, -1);
        mpz_mul(aux2, m, m);
        mpz_add(aux1, aux1, aux2);
        mpz_mod(Sumx, aux1, modulo_base);

        mpz_sub(aux1, P1xaux, Sumx);
        mpz_mul(aux1, aux1, m);
        mpz_sub(aux1, aux1, P1y);
        mpz_mod(Sumy, aux1, modulo_base);

}

void multiply_point(mpz_t Rezx, mpz_t Rezy, mpz_t Px, mpz_t Py, mpz_t scalar, mpz_t modulo_base) //Rez=scalar*P
{
    mpz_t doi_in_mpz, aux, acumulatorx, acumulatory; mpz_inits(doi_in_mpz, aux, acumulatorx, acumulatory, NULL);
    mpz_set_si(doi_in_mpz, 2);
    int steag_rez_neinitializat = 1;

    mpz_mod(aux, scalar, doi_in_mpz);
    if( mpz_cmp_ui(aux, 1) == 0 ) {
        mpz_set(Rezx, Px); mpz_set(Rezy, Py);
        steag_rez_neinitializat = 0;
        mpz_set(acumulatorx, Px); mpz_set(acumulatory, Py);
        mpz_fdiv_q(scalar, scalar, doi_in_mpz);
    }
    else {
        mpz_set(acumulatorx, Px); mpz_set(acumulatory, Py);
        mpz_fdiv_q(scalar, scalar, doi_in_mpz);
        mpz_mod(aux, scalar, doi_in_mpz);

        while( mpz_cmp_ui(aux, 0) == 0 ) {
            add_point(acumulatorx, acumulatory, acumulatorx, acumulatory, acumulatorx, acumulatory, modulo_base);
            mpz_fdiv_q(scalar, scalar, doi_in_mpz);
            mpz_mod(aux, scalar, doi_in_mpz);
        }  
    }
    while( mpz_cmp_si(scalar, 0) != 0)  //algoritmul Double and Add
    {
        add_point(acumulatorx, acumulatory, acumulatorx, acumulatory, acumulatorx, acumulatory, modulo_base); //Double
        mpz_mod(aux, scalar, doi_in_mpz); //calculez ce a ramas din cheie mod 2

        if( mpz_cmp_ui(aux, 1) == 0 && (steag_rez_neinitializat == 0) ) {
            add_point(Rezx, Rezy, acumulatorx, acumulatory, Rezx, Rezy, modulo_base);   //Add
        }

        if( mpz_cmp_ui(aux, 1) == 0 && (steag_rez_neinitializat == 1) ) {
            mpz_set(Rezx, acumulatorx); mpz_set(Rezy, acumulatory);
            steag_rez_neinitializat = 0;
        }
        mpz_fdiv_q(scalar, scalar, doi_in_mpz);
    }
}

#define ___min( x, y )  (((x) < (y))?(x):(y))
#define BUFFER_SIZE             1024

static
void
    ReadHexData
    (
        char const*         HexString,          // [in]
        uint8_t*            Data,               // [out]
        uint32_t*           pDataSize           // [in out]
    )
{
    uint32_t        i;
    char            holdingBuffer [3] = {0};
    uint32_t        holdingBufferIndex = 0;
    unsigned        hexToNumber;
    unsigned        outputIndex = 0;

    for( i=0; i<strlen(HexString); i++ )
    {
        if(     ( HexString[i] >= '0' && HexString[i] <= '9' )
            ||  ( HexString[i] >= 'A' && HexString[i] <= 'F' )
            ||  ( HexString[i] >= 'a' && HexString[i] <= 'f' ) )
        {
            holdingBuffer[holdingBufferIndex] = HexString[i];
            holdingBufferIndex += 1;

            if( 2 == holdingBufferIndex )
            {
                // Have two digits now so read it as a byte.
                sscanf( holdingBuffer, "%x", &hexToNumber );
                Data[outputIndex] = (uint8_t) hexToNumber;
                outputIndex += 1;
                if( outputIndex == *pDataSize )
                {
                    // No more space so stop reading
                    break;
                }
                holdingBufferIndex = 0;
            }
        }
    }

    *pDataSize = outputIndex;
}

void
    AES_RNG_CTR
    (
        char*          key_input,
        char*          IV_input,
        uint32_t       numBytes,
        FILE*          fisier
    )
{
    uint32_t        i;
    uint8_t         buffer [BUFFER_SIZE];
    uint32_t        amountLeft;
    uint32_t        chunk;
    AesCtrContext   aesCtr;
    uint8_t         key [AES_KEY_SIZE_256];
    uint32_t        keySize = sizeof(key);
    uint8_t         IV [AES_CTR_IV_SIZE];
    uint32_t        IVSize = sizeof(IV);

    ReadHexData( key_input, key, &keySize );
    ReadHexData( IV_input, IV, &IVSize );

    AesCtrInitialiseWithKey( &aesCtr, key, keySize, IV );

    amountLeft = numBytes;
    while( amountLeft > 0 )
    {
        chunk = ___min( amountLeft, BUFFER_SIZE );
        AesCtrOutput( &aesCtr, buffer, chunk );
        amountLeft -= chunk;

        for( i=0; i<chunk; i++ )
        {
            fprintf(fisier, "%2.2x", buffer[i] );
        }
    }
    fprintf(fisier, "\n");
}

int main ()
{
    mpz_t p, b, Gx, Gy, Rx, Ry, local_key; mpz_inits(p, b, Gx, Gy, Rx, Ry, local_key, NULL); //y^2 = x^3-3x+b (mod p)

    mpz_set_str(p, "115792089210356248762697446949407573530086143415290314195533631308867097853951", 10);  //parametrii curbei P-256
    mpz_set_str(b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16); 
    mpz_set_str(Gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(Gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);


    FILE* fisier;
    fisier = fopen("input_keys.txt", "w+");
    if(fisier == NULL)
    {
        printf("Input keys file not found\n");
        return 0;
    }

    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000000", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000001", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000002", 32, fisier);

    char** keys_array; int i=0;
    keys_array=(char**)malloc(NB_KEYS*sizeof(char*));
    for(i=0; i<NB_KEYS; i++)
    {
        keys_array[i] = (char*)malloc(200*sizeof(char));
    }
    i=0;
    fseek(fisier, 0, SEEK_SET);
    while (!feof(fisier)) 
    {
        fgets(keys_array[i], 200, fisier);
        i++;
    }

    FILE* fisier_output;
    fisier_output = fopen("output_points.txt", "w+");
    if(fisier_output == NULL)
    {
        printf("Output points file not found\n");
        return 0;
    }

    for(i=0; i<NB_KEYS; i++)
    {
        mpz_set_str(local_key, keys_array[i], 16);
        multiply_point(Rx, Ry, Gx, Gy, local_key, p);
        gmp_fprintf(fisier_output, "Rx = %Zx\nRy = %Zx\n\n", Rx, Ry);
    }

    return 0;
}