#include <stdio.h>
#include <sys/time.h>
#include "mycrypto.h"

#define TIME_REP 10000


double gtd(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec/1000000.0;
}

int main()
{   
    double st, et;

    unsigned char pt[] = "Two One Nine Two";
    unsigned char key[] = "Thats my Kung Fu";
    printf("Plain text: %s\nKey: %s\n", pt, key);

    // AES128 naive
    uint8_t ct_naive[17] = {0};
    uint8_t dt_naive[17] = {0};
    uint8_t key_schedule_naive[11][16] = {0};
    
    AES128_Loadkey_naive(key, key_schedule_naive);
    st = gtd();
    for(int i=0;i<TIME_REP;i++){
        AES128_Encrypt_naive(pt, key_schedule_naive, ct_naive);
        AES128_Decrypt_naive(ct_naive, key_schedule_naive, dt_naive);
    }
    et = gtd();
    
    printf("\nAES128-naive: \n");
    printf("timeing: %.9lfs\n", (et-st)/TIME_REP);
    printf("ciphertext: ");
    for(int i=0;i<16;i++) printf("%02x ", ct_naive[i]);
    putchar('\n');
    printf("decrypted text: %s\n", dt_naive);


    // AES128 x86 AES-NI
    unsigned char ct[17] = {0};
    unsigned char dt[17] = {0};
    __m128i key_schedule[20];

    AES128_Loadkey_x86(key, key_schedule);
    st = gtd();
    for(int i=0;i<TIME_REP;i++){
        AES128_Encrypt_x86(pt, key_schedule, ct);
        AES128_Decrypt_x86(ct, key_schedule, dt);
    }
    et = gtd();
    
    printf("\nAES128-x86: \n");
    printf("timeing: %.9lfs\n", (et-st)/TIME_REP);
    printf("ciphertext: ");
    for(int i=0;i<16;i++) printf("%02x ", ct[i]);
    putchar('\n');
    printf("decrypted text: %s\n", dt);




    return 0;
}