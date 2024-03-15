#undef ECC_TIMING_RESISTANT
#include <stdint.h>
#include "stdio.h"
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
#define OPENSSL_EXTRA
#undef ECC_TIMING_RESISTANT


int main() {
    ecc_key key;
    int ret;
    WC_RNG rng;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    int curveId = ECC_SECP256R1;
    int keySize = wc_ecc_get_curve_size_from_id(curveId);
    ret = wc_ecc_make_key_ex(&rng, keySize, &key, curveId);

    //get param of ecc curve
    mp_int a,b,prime,order,ra,s;
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
    printf("mp_int s: %i\n", ret);

    

    ecc_point* pointG = wc_ecc_new_point();
    ret = wc_ecc_get_generator(pointG,wc_ecc_get_curve_idx(ECC_SECP256R1));
    printf("get ecc_point pointG: %i\n", ret);
    //sp_print(pointG->x, "");
    ret = wc_ecc_is_point(pointG,&a,&b,&prime);
    printf("point is on curve: %i\n", ret);


//tes1:n1 = 10,n2 = 33,n3 = n1*n2, A = n3*G,B = n2*G,C = n1*B=> A == C
    mp_int n1,n2,n3;
    mp_init_multi(&n1,&n2,&n3,NULL,NULL,NULL);
    mp_set_int(&n1,10);
    mp_set_int(&n2,33);
    ret = mp_mulmod(&n1,&n2,&prime,&n3);
    ecc_point* A = wc_ecc_new_point();
    ecc_point* B = wc_ecc_new_point();
    ecc_point* C = wc_ecc_new_point();
    ret = wc_ecc_mulmod(&n3,pointG,A,&a,&prime,1);
    printf("n3*G: %i\n", ret);

    ret = wc_ecc_mulmod(&n1,pointG,B,&a,&prime,1);
    printf("n1*G: %i\n", ret);

    ret = wc_ecc_mulmod(&n2,B,C,&a,&prime,1);
    printf("n2*B: %i\n", ret);

    ret = wc_ecc_cmp_point(A,C);
    printf("A is equal to C: %i\n", ret);

//test2:ra1,ra2 are big number ra3 = ra1*ra2, D = ra3*G,E = ra2*G,F = ra1*E=> D != F
    mp_int ra1,ra2,ra3;
    mp_init_multi(&ra1,&ra2,&ra3,NULL,NULL,NULL);

    ret = wc_ecc_gen_k(&rng,32,&ra1,&order);
    printf("get mp_int ra1: %i\n", ret);

    ret = wc_ecc_gen_k(&rng,32,&ra2,&order);
    printf("get mp_int ra2: %i\n", ret);

    ret = mp_mulmod(&ra1,&ra2,&order,&ra3);
    ecc_point* D = wc_ecc_new_point();
    ecc_point* E =wc_ecc_new_point();
    ecc_point* F =wc_ecc_new_point();

    ret = wc_ecc_mulmod(&ra3,pointG,D,&a,&prime,1);
    printf("ra3*G: %i\n", ret);

    ret = wc_ecc_mulmod(&ra1,pointG,E,&a,&prime,1);
    printf("ra1*G: %i\n", ret);

    ret = wc_ecc_mulmod(&ra2,E,F,&a,&prime,1);
    printf("ra2*E: %i\n", ret);

    ret = wc_ecc_cmp_point(D,F);
    printf("D is equal to F: %i\n", ret);
    sp_print(F->x, "Fx");
    sp_print(D->x, "Dx");
    return 0;
}