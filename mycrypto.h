#include <stdint.h>
#include "wmmintrin.h"

// AES128 naive C implementation
void AES128_Loadkey_naive(const uint8_t* key, uint8_t (*key_schedule)[16]);
void AES128_Encrypt_naive(const uint8_t* plaintext, const uint8_t (*key_schedule)[16], uint8_t* ciphertext);
void AES128_Decrypt_naive(const uint8_t* ciphertext, const uint8_t (*key_schedule)[16], uint8_t* plaintext);

// AES128 x86 AES-NI intrinsics implementation
void AES128_Loadkey_x86(const uint8_t* key, __m128i* key_schedule);
void AES128_Encrypt_x86(const uint8_t* plaintext, const __m128i* key_schedule, uint8_t* ciphertext);
void AES128_Decrypt_x86(const uint8_t* ciphertext, const __m128i* key_schedule, uint8_t* plaintext);