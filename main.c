#undef ECC_TIMING_RESISTANT
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sp_int.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "WJ/WjCryptLib_AesCtr.h"
#include <stdlib.h>

#ifndef __min
   #define __min( x, y )  (((x) < (y))?(x):(y))
#endif

#define BUFFER_SIZE_AES             1024

//  ReadHexData
//
//  Reads a string as hex and places it in Data. *pDataSize on entry specifies maximum number of bytes that can be
//  read, and on return is set to how many were read. This will be zero if it failed to read any.
//  This function ignores any character that isn't a hex character.
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
        mp_int*        output
    )
{
    uint32_t        i;
    uint8_t         buffer [BUFFER_SIZE_AES];
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
    mp_int aux; mp_init(&aux);
    while( amountLeft > 0 )
    {
        chunk = __min( amountLeft, BUFFER_SIZE_AES );
        AesCtrOutput( &aesCtr, buffer, chunk );
        amountLeft -= chunk;
        for( i=0; i<chunk; i++ )
            {   
                mp_mul_2d(output, 8, output);
                mp_set_int(&aux, buffer[i]);
                mp_add(output, &aux, output);
            }
    }
}

#define OPENSSL_EXTRA
#undef ECC_TIMING_RESISTANT


int main() {
    int curveId = ECC_SECP256R1;
    //int ret;

    /*ecc_key key;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);*/ //partea asta foloseste doar la generarea rng ului

    //generate random numbers based on aes ctr;
    //1st arg: key (128/192/256 bits written in hex)
    //2nd arg: IV (64 bits in hex)
    //3rd arg: desired length of pseudo random sequence
    //mp_int aess; mp_init(&aess); AES_RNG_CTR("00000000000000000000000000000000", "0000000000000000", 32, &aess); sp_print(&aess, "aess");


    //get param of ecc curve
    /*mp_int a, b, prime, order, ra, s;
    mp_init_multi(&a,&b,&prime,&order,&ra,&s);
    ret = mp_read_radix(&a,key.dp->Af,16);
    printf("mp_int af: %i\n", ret);

    ret = mp_read_radix(&b,key.dp->Bf,16);
    printf("mp_int bf: %i\n", ret);

    ret = mp_read_radix(&prime,key.dp->prime,16);
    printf("mp_int prime: %i\n", ret);

    ret = mp_read_radix(&order,key.dp->order,16);
    printf("mp_int order: %i\n", ret);

    ret = wc_ecc_gen_k(&rng,32,&ra,&order);
    printf("mp_int ra: %i\n", ret);

    ret = mp_copy(key.k,&s);
    printf("mp_int s: %i\n", ret);*/

    //scoaterea functiilor
    //ecc_point* pointG = wc_ecc_new_point();
    //ret = wc_ecc_get_generator(pointG,wc_ecc_get_curve_idx(curveId));
    //printf("get ecc_point pointG: %i\n", ret);
    //sp_print(pointG->x, "Gx");
    //sp_print(pointG->y, "Gy");
    //ret = wc_ecc_is_point(pointG,&a,&b,&prime);
    //printf("point is on curve: %i\n", ret);


    //wc_get_curve_params pour lire les paramètres de la courbe (convertir les chaînes de caractères avec mp_read_radix)
    const ecc_set_type* curve_params;
    curve_params = wc_ecc_get_curve_params(4);
    mp_int gx,gy,prime,order,a; mp_init_multi(&gx,&gy,&prime,&order,&a,NULL);
    mp_read_radix(&gx, curve_params[0].Gx, 16);
    mp_read_radix(&gy, curve_params[0].Gy, 16);
    mp_read_radix(&prime, curve_params[0].prime, 16);
    mp_read_radix(&order, curve_params[0].order, 16);
    mp_read_radix(&a, curve_params[0].Af, 16);
    sp_print(&prime, "prime");
    sp_print(&order, "order");
    sp_print(&a, "a");

    ecc_point* pointG = wc_ecc_new_point();
    mp_int one; mp_init(&one); mp_set_int(&one, 1);
    *pointG->x = gx; *pointG->y = gy; *pointG->z = one;
    sp_print(pointG->x, "Gx");
    sp_print(pointG->y, "Gy");

//tes1:n1 = 2, n2 = 3, n3 = n1 * n2 = 6, A = n3 * G = 6G, B = n2 * G = 3G, C = n1 * B = 2*(3*G) = 6G => A == C
    mp_int n1,n2,n3;
    mp_init_multi(&n1,&n2,&n3,NULL,NULL,NULL);
    mp_set_int(&n1,2);
    mp_set_int(&n2,3);
    mp_mulmod(&n1,&n2,&prime,&n3);
    ecc_point* A = wc_ecc_new_point();
    ecc_point* B = wc_ecc_new_point();
    ecc_point* C = wc_ecc_new_point();

    wc_ecc_mulmod(&n3,pointG,A,&a,&prime,1); //A=n3*G

    //sp_print(pointG->x, "Gx");
    sp_print(A->x, "Ax (6G)");

    wc_ecc_mulmod(&n1,pointG,B,&a,&prime,1); //B=n1*G
    sp_print(B->x, "Bx (2G)");
    //printf("n1*G: %i\n", ret);

    wc_ecc_mulmod(&n2,B,C,&a,&prime,1);
    sp_print(C->x, "Cx (6G)");

    //printf("n2*B: %i\n", ret);
    //ret = wc_ecc_cmp_point(A,C);
    //printf("A is equal to C: %i\n", ret);

//test2:ra1,ra2 are big numbers; ra3 = ra1*ra2, D = ra3*G,E = ra2*G,F = ra1*E=> D == F
    mp_int ra1,ra2,ra3; mp_init_multi(&ra1,&ra2,&ra3,NULL,NULL,NULL);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000000", 32, &ra1);
    AES_RNG_CTR("00000000000000000000000000000000", "0000000000000000", 32, &ra2);
    
    sp_print(&ra1, "ra1"); sp_print(&ra2, "ra2");

    mp_mulmod(&ra1,&ra2,&order,&ra3);
    ecc_point* D = wc_ecc_new_point();
    ecc_point* E = wc_ecc_new_point();
    ecc_point* F = wc_ecc_new_point();

    wc_ecc_mulmod(&ra3,pointG,D,&a,&prime,1); //D = ra3*G
    wc_ecc_mulmod(&ra1,pointG,E,&a,&prime,1); //E = ra1*G
    wc_ecc_mulmod(&ra2,E,F,&a,&prime,1);      //F = ra2*E

    sp_print(F->x, "Fx");
    sp_print(E->x, "Ex");
    sp_print(D->x, "Dx");
    return 0;
}
