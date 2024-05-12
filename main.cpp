#include <cstdio>
#include <cstring>
#include <sys/time.h>
#include "mycrypto.h"
#include "myhash.h"

#define TIME_REP 100000
#define TIMING(code, result) \
        {\
            double st=gtd();\
            for(int i=0; i<TIME_REP; i++) {code}\
            double et=gtd(); \
            result = (et-st)/TIME_REP;\
        }\


double gtd(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000.0 + tv.tv_usec/1000.0;
}

int main()
{
    // AES128 naive
    unsigned char pt_aes[] = "I want to sleep!";
    unsigned char key_aes[] = "I want to sleep!";
    unsigned char ct_true[] = {0x70, 0xf4, 0x96, 0x78, 0x90, 0xdc, 0xff, 0x7a, 0xec, 0x45, 0xbc, 0xf9, 0xae, 0x09, 0xfc, 0x63, '\0'};
    uint8_t ct_naive[17] = {0};
    uint8_t dt_naive[17] = {0};
    uint8_t key_schedule_naive[11][16] = {0};
    double lapse_aes128_naive_keygen, lapse_aes128_naive_enc, lapse_aes128_naive_dec;
    TIMING(AES128_KeyExpd_naive(key_aes, key_schedule_naive);, lapse_aes128_naive_keygen)
    TIMING(AES128_Encrypt_naive(pt_aes, key_schedule_naive, ct_naive);, lapse_aes128_naive_enc)
    TIMING(AES128_Decrypt_naive(ct_naive, key_schedule_naive, dt_naive);, lapse_aes128_naive_dec)
    
    printf("[AES128-naive]: \n");
    printf("timing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf\n", lapse_aes128_naive_keygen, lapse_aes128_naive_enc, lapse_aes128_naive_dec);
    printf("plaintext: %s\n", pt_aes);
    printf("ciphertext: "); for(int i=0;i<16;i++) printf("%02x ", ct_naive[i]); putchar('\n');
    printf("EncryptCheck: %s\n", strcmp((char*)ct_true, (char*)ct_naive) ? "Fail" : "Pass");
    printf("decrypttext: %s\n", dt_naive);

    // AES128 x86 AES-NI
    unsigned char ct_x86[17] = {0};
    unsigned char dt_x86[17] = {0};
    __m128i key_schedule[20];
    double lapse_aes128_x86_keygen, lapse_aes128_x86_enc, lapse_aes128_x86_dec;
    TIMING(AES128_KeyExpd_x86(key_aes, key_schedule);, lapse_aes128_x86_keygen)
    TIMING(AES128_Encrypt_x86(pt_aes, key_schedule, ct_x86);, lapse_aes128_x86_enc)
    TIMING(AES128_Decrypt_x86(ct_x86, key_schedule, dt_x86);, lapse_aes128_x86_dec)
    
    printf("\n[AES128-x86]: \n");
    printf("timing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf\n", lapse_aes128_x86_keygen, lapse_aes128_x86_enc, lapse_aes128_x86_dec);
    printf("plaintext: %s\n", pt_aes);
    printf("ciphertext: "); for(int i=0;i<16;i++) printf("%02x ", ct_x86[i]); putchar('\n');
    printf("EncryptCheck: %s\n", strcmp((char*)ct_true, (char*)ct_x86) ? "Fail" : "Pass");
    printf("decrypttext: %s\n", dt_x86);


    // SM4 naive
    unsigned char pt_sm4[17] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, '\0'};
    unsigned char key_sm4[16]= {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char ct_sm4_ref[17] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, '\0'};
    unsigned char ct_sm4[17] = {0};
    unsigned char dt_sm4[17] = {0};
    uint32_t key_schedule_sm4[32];
    double lapse_sm4_keygen, lapse_sm4_enc, lapse_sm4_dec;
    TIMING(SM4_KeyExpd_naive(key_sm4, key_schedule_sm4);, lapse_sm4_keygen)
    TIMING(SM4_Encrypt_naive(pt_sm4, key_schedule_sm4, ct_sm4);, lapse_sm4_enc)
    TIMING(SM4_Decrypt_naive(ct_sm4, key_schedule_sm4, dt_sm4);, lapse_sm4_dec)

    printf("\n[SM4-naive]: \n");
    printf("timing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf\n", lapse_sm4_keygen, lapse_sm4_enc, lapse_sm4_dec);
    printf("ciphertext: "); for(int i=0; i<16; i++) printf("%x ", ct_sm4[i]); putchar('\n');
    printf("EncryptCheck: %s\n", strcmp((char*)ct_sm4_ref, (char*)ct_sm4) ? "Fail" : "Pass");
    printf("decrypttext: "); for(int i=0; i<16; i++) printf("%02x ", dt_sm4[i]); putchar('\n');
    printf("DecryptCheck: %s\n", strcmp((char*)pt_sm4, (char*)dt_sm4) ? "Fail" : "Pass");


    // SHA3 256 & 512 naive
    unsigned char sha3_msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t hash_sha3_256[32];
    double lapse_sha3_256;
    TIMING(SHA3_256_naive(56, sha3_msg, hash_sha3_256);, lapse_sha3_256)
    uint8_t hash_sha3_512[64];
    double lapse_sha3_512;
    TIMING(SHA3_512_naive(56, sha3_msg, hash_sha3_512);, lapse_sha3_512)

    printf("\n[SHA3-naive]: \n");
    printf("timing(sha3-256)(ms): %.9lf\n", lapse_sha3_256);
    printf("timing(sha3-512)(ms): %.9lf\n", lapse_sha3_512);
    printf("SHA3-256 hash(reference): %s\n", "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376");
    printf("SHA3-256 hash           : "); for(int i=0; i<32; i++){printf("%02x", hash_sha3_256[i]); if(i%8==7) printf(" ");} putchar('\n');
    printf("SHA3-512 hash(reference): %s\n", "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e");
    printf("SHA3-512 hash           : "); for(int i=0; i<64; i++){printf("%02x", hash_sha3_512[i]); if(i%8==7) printf(" ");} putchar('\n');

    
    // SM3 naive
    unsigned char sm3_msg[] = "I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep! I want to sleep!";
    uint8_t hash_sm3[32];
    double lapse_sm3;
    TIMING(SM3_256_naive(271, sm3_msg, hash_sm3);, lapse_sm3)

    printf("\n[SM3-naive]: \n");
    printf("timing(ms): %.9lf\n", lapse_sm3);
    printf("SM3 hash(reference): %s\n", "2F7274F4 D8337FD6 8C940FAF 6C26BDB0 0129EB67 F925298E 6945B71E CE00B2F6");
    printf("SM3 hash           : "); for(int i=0; i<32; i++) {printf("%02x", hash_sm3[i]); if(i%4==3) putchar(' ');}; putchar('\n');


    // XTS_AES128
    unsigned char pt_xts[32] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    unsigned char ct_xts[33]={0};
    unsigned char ct_ref_xts[33]={0xaf, 0x85, 0x33, 0x6b, 0x59, 0x7a, 0xfc, 0x1a, 0x90, 0x0b, 0x2e, 0xb2, 0x1e, 0xc9, 0x49, 0xd2,
                                  0x92, 0xdf, 0x4c, 0x04, 0x7e, 0x0b, 0x21, 0x53, 0x21, 0x86, 0xa5, 0x97, 0x1a, 0x22, 0x7a, 0x89, '\0'};
    unsigned char dt_xts[32]={0};
    uint8_t key_xts[32] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
                           0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    uint64_t seq_num = 0x3333333333;
    size_t msg_size = 32;
    
    XTS_AES128_Encrypt_naive(pt_xts, msg_size, seq_num, key_xts, ct_xts);
    XTS_AES128_Decrypt_naive(ct_xts, msg_size, seq_num, key_xts, dt_xts);
    printf("\n[XTS-AES128-naive]: \n");
    printf("timing(ms): %.9lf\n", lapse_sm3);
    printf("plaintext: "); for(size_t i=0;i<msg_size;i++) printf("%02x ", pt_xts[i]); putchar('\n');
    printf("ciphertext: "); for(size_t i=0;i<msg_size;i++) printf("%02x ", ct_xts[i]); putchar('\n');
    printf("EncryptoCheck: %s\n", strcmp((char*)ct_xts, (char*)ct_ref_xts)?"Fail":"Pass");
    printf("deciphertext: "); for(size_t i=0;i<msg_size;i++) printf("%02x ", dt_xts[i]); putchar('\n');

    return 0;
}