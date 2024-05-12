#include <cstdio>
#include <cstring>
#include <sys/time.h>
#include "mycrypto.h"
#include "myhash.h"

#define TIME_REP 1
#define TIMING(code, result) \
        {\
            double st=gtd();\
            for(int tttt=0; tttt<TIME_REP; tttt++) {code}\
            double et=gtd(); \
            result = (et-st)/TIME_REP;\
        }\


double gtd(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000.0 + tv.tv_usec/1000.0;
}

int main(){
    uint8_t * data_16k = (uint8_t*)malloc(1<<14);
    uint8_t * data_4M = (uint8_t*)malloc(1<<22);
    uint8_t * data_1G = (uint8_t*)malloc(1<<30);
    uint8_t * buff_1G = (uint8_t*)malloc(1<<30);

    int data_size = 1<<26;
    uint8_t * data_use = data_1G;
    uint8_t * buff_use = buff_1G;

    // AES128 naive
    unsigned char key_aes[] = "I want to sleep!";
    uint8_t key_schedule_naive[11][16] = {0};
    double lapse_aes128_naive_enc, lapse_aes128_naive_dec;
    AES128_KeyExpd_naive(key_aes, key_schedule_naive);

    TIMING(
        for(int i=0; i<(data_size/16); i++)
            AES128_Encrypt_naive((data_use+i*16), key_schedule_naive, (buff_use+i*16));
        , lapse_aes128_naive_enc
    )
    TIMING(
        for(int i=0; i<(data_size/16); i++)
            AES128_Encrypt_naive((data_use+i*16), key_schedule_naive, (buff_use+i*16));
        , lapse_aes128_naive_enc
    )
    TIMING(
        for(int i=0; i<(data_size/16); i++)
            AES128_Decrypt_naive((data_use+i*16), key_schedule_naive, (buff_use+i*16));
        , lapse_aes128_naive_dec
    )
    
    printf("[AES128-naive]: \n");
    printf("timing(enc,dec)(ms): %.9lf, %.9lf, %.9lf, %.9lf\n", lapse_aes128_naive_enc, lapse_aes128_naive_dec, (1000.0*data_size)/(2<<20)/lapse_aes128_naive_enc, (1000.0*data_size)/(2<<20)/lapse_aes128_naive_dec);


    __m128i key_schedule[20];
    double lapse_aes128_x86_enc, lapse_aes128_x86_dec;
    AES128_KeyExpd_x86(key_aes, key_schedule);

    TIMING(
        for(int i=0; i<(data_size/16); i++)
            AES128_Encrypt_x86(data_use, key_schedule, buff_use);
        , lapse_aes128_x86_enc)
    TIMING(
        for(int i=0; i<(data_size/16); i++)
            AES128_Decrypt_x86(data_use, key_schedule, buff_use);
        , lapse_aes128_x86_dec)
    
    printf("\n[AES128-x86]: \n");
    printf("timing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf, %.9lf\n", lapse_aes128_x86_enc, lapse_aes128_x86_dec, (1000.0*data_size)/(2<<20)/lapse_aes128_x86_enc, (1000.0*data_size)/(2<<20)/lapse_aes128_x86_dec);



    // SM4 naive
    unsigned char key_sm4[16]= {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char ct_sm4[17] = {0};
    unsigned char dt_sm4[17] = {0};
    uint32_t key_schedule_sm4[32];
    double lapse_sm4_enc, lapse_sm4_dec;
    SM4_KeyExpd_naive(key_sm4, key_schedule_sm4);

    TIMING(
        for(int i=0; i<(data_size/16); i++)
            SM4_Encrypt_naive((data_use+i*16), key_schedule_sm4, ct_sm4);
        , lapse_sm4_enc)
    
    TIMING(
        for(int i=0; i<(data_size/16); i++)
            SM4_Decrypt_naive((data_use+i*16), key_schedule_sm4, dt_sm4);
        , lapse_sm4_dec)

    printf("\n[SM4-naive]: \n");
    printf("timing(enc,dec)(ms): %.9lf, %.9lf, %.9lf, %.9lf\n", lapse_sm4_enc, lapse_sm4_dec, (1000.0*data_size)/(2<<20)/lapse_sm4_enc, (1000.0*data_size)/(2<<20)/lapse_sm4_dec);


    // XTS-AES
    uint8_t key_xts[32] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    uint64_t seq_num = 0x3333333333;
    size_t msg_size = data_size;
    double lapse_xts_enc, lapse_xts_dec;
    TIMING(
        XTS_AES128_Encrypt_naive(data_use, msg_size, seq_num, key_xts, buff_use);
        , lapse_xts_enc);
    TIMING(
        XTS_AES128_Decrypt_naive(data_use, msg_size, seq_num, key_xts, buff_use);
        , lapse_xts_dec);
    
    printf("\n[XTS-AES128-naive]: \n");
    printf("timing(ms)(Enc,Dec): %.9lf, %.9lf, %.9lf, %.9lf\n", lapse_xts_enc, lapse_xts_dec, (1000.0*data_size)/(2<<20)/lapse_xts_enc, (1000.0*data_size)/(2<<20)/lapse_xts_dec);


    uint8_t hash_sm3[32];
    double lapse_sm3;
    TIMING(SM3_256_naive(data_size, data_use, hash_sm3);, lapse_sm3)

    printf("\n[SM3-naive]: \n");
    printf("timing(ms): %.9lf, %.9lf\n", lapse_sm3, (1000.0*data_size)/(2<<20)/lapse_sm3);

    // XTS-AES
    uint8_t hash_sha3_256[32];
    double lapse_sha3_256;
    TIMING(SHA3_256_naive(data_size, data_use, hash_sha3_256);, lapse_sha3_256)
    uint8_t hash_sha3_512[64];
    double lapse_sha3_512;
    TIMING(SHA3_512_naive(data_size, data_use, hash_sha3_512);, lapse_sha3_512)

    printf("\n[SHA3-naive]: \n");
    printf("timing(sha3-256)(ms): %.9lf, %.9lf\n", lapse_sha3_256, (1000.0*data_size)/(2<<20)/lapse_sha3_256);
    printf("timing(sha3-512)(ms): %.9lf, %.9lf\n", lapse_sha3_512, (1000.0*data_size)/(2<<20)/lapse_sha3_512);
}