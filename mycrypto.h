#include <stdint.h>
#include "wmmintrin.h"


// AES128 naive C implementation
void AES128_KeyExpd_naive(const uint8_t* key, uint8_t (*key_schedule)[16]);
void AES128_Encrypt_naive(const uint8_t* plaintext, const uint8_t (*key_schedule)[16], uint8_t* ciphertext);
void AES128_Decrypt_naive(const uint8_t* ciphertext, const uint8_t (*key_schedule)[16], uint8_t* plaintext);

// AES128 x86 AES-NI intrinsics implementation
void AES128_KeyExpd_x86(const uint8_t* key, __m128i* key_schedule);
void AES128_Encrypt_x86(const uint8_t* plaintext, const __m128i* key_schedule, uint8_t* ciphertext);
void AES128_Decrypt_x86(const uint8_t* ciphertext, const __m128i* key_schedule, uint8_t* plaintext);

// XTS-AES128 naive C implementation
void XTS_AES128_Encrypt_naive(const uint8_t* pt, const size_t pt_size, const uint64_t seq_num, const uint8_t* key, uint8_t* ct);
void XTS_AES128_Decrypt_naive(const uint8_t* ct, const size_t ct_size, const uint64_t seq_num, const uint8_t* key, uint8_t* pt);

// SM4 naive C implementation
void SM4_KeyExpd_naive(const uint8_t* key, uint32_t* key_schedule);
void SM4_Encrypt_naive(const uint8_t* plaintext, const uint32_t* key_schedule, uint8_t* ciphertext);
void SM4_Decrypt_naive(const uint8_t* ciphertext, const uint32_t* key_schedule, uint8_t* plaintext);