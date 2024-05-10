#include <cstdio>
#include <cstring>
#include <sys/time.h>
#include "mycrypto.h"

#define TIME_REP 10000


double gtd(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec/1000.0;
}

int main()
{   
    double st0, et0, st1, et1, st2, et2;

    unsigned char pt[] = "Two One Nine Two";
    unsigned char key[] = "Thats my Kung Fu";
    printf("Plain text: %s\nKey: %s\n", pt, key);

    // AES128 naive
    uint8_t ct_naive[17] = {0};
    uint8_t dt_naive[17] = {0};
    uint8_t key_schedule_naive[11][16] = {0};
    

    st0 = gtd();
    for(int i=0;i<TIME_REP;i++) AES128_KeyExpd_naive(key, key_schedule_naive);
    et0 = gtd();
    st1 = gtd();
    for(int i=0;i<TIME_REP;i++) AES128_Encrypt_naive(pt, key_schedule_naive, ct_naive);
    et1 = gtd();
    st2 = gtd();
    for(int i=0;i<TIME_REP;i++) AES128_Decrypt_naive(ct_naive, key_schedule_naive, dt_naive);
    et2 = gtd();
    
    printf("\n[AES128-naive]: \n");
    printf("timeing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf\n", (et0-st0)/TIME_REP, (et1-st1)/TIME_REP, (et2-st2)/TIME_REP);
    printf("ciphertext: "); for(int i=0;i<16;i++) printf("%02x ", ct_naive[i]); putchar('\n');
    printf("decrypttext: %s\n", dt_naive);


    // AES128 x86 AES-NI
    unsigned char ct[17] = {0};
    unsigned char dt[17] = {0};
    __m128i key_schedule[20];

    st0 = gtd();
    for(int i=0;i<TIME_REP;i++) AES128_KeyExpd_x86(key, key_schedule);
    et0 = gtd();
    st1 = gtd();
    for(int i=0;i<TIME_REP;i++) AES128_Encrypt_x86(pt, key_schedule, ct); 
    et1 = gtd();
    st2 = gtd();
    for(int i=0;i<TIME_REP;i++) AES128_Decrypt_x86(ct, key_schedule, dt);
    et2 = gtd();
    
    printf("\n[AES128-x86]: \n");
    printf("timeing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf\n", (et0-st0)/TIME_REP, (et1-st1)/TIME_REP, (et2-st2)/TIME_REP);
    printf("ciphertext: "); for(int i=0;i<16;i++) printf("%02x ", ct[i]); putchar('\n');
    printf("decrypttext: %s\n", dt);


    // SM4 naive
    unsigned char pt_sm4[17] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, '\0'};
    unsigned char key_sm4[16]= {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char ct_sm4_ref[17] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, '\0'};
    unsigned char ct_sm4[17] = {0};
    unsigned char dt_sm4[17] = {0};
    uint32_t key_schedule_sm4[32];

    st0 = gtd();
    for(int i=0;i<TIME_REP;i++) SM4_KeyExpd_naive(key_sm4, key_schedule_sm4);
    et0 = gtd();
    st1 = gtd();
    for(int i=0;i<TIME_REP;i++) SM4_Encrypt_naive(pt_sm4, key_schedule_sm4, ct_sm4); 
    et1 = gtd();
    st2 = gtd();
    for(int i=0;i<TIME_REP;i++) SM4_Decrypt_naive(ct_sm4, key_schedule_sm4, dt_sm4);
    et2 = gtd();

    printf("\n[SM4-naive]: \n");
    printf("timeing(kengen,enc,dec)(ms): %.9lf, %.9lf, %.9lf\n", (et0-st0)/TIME_REP, (et1-st1)/TIME_REP, (et2-st2)/TIME_REP);
    printf("ciphertext: "); for(int i=0; i<16; i++) printf("%x ", ct_sm4[i]); putchar('\n');
    printf("SM4 Encrypt Check: %s\n", strcmp((char*)ct_sm4_ref, (char*)ct_sm4) ? "Fail" : "Pass");
    printf("decrypttext: "); for(int i=0; i<16; i++) printf("%02x ", dt_sm4[i]); putchar('\n');
    printf("SM4 Decrypt Check: %s\n", strcmp((char*)pt_sm4, (char*)dt_sm4) ? "Fail" : "Pass");


    return 0;
}