#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wmmintrin.h"
#include "mycrypto.h"

#define U8TO32_STRIDE4(x) ( (((uint32_t)((x)[12]))<<24) | (((uint32_t)((x)[8]))<<16)  | (((uint32_t)((x)[4]) << 8)) | ((uint32_t)((x)[0])) )
#define ROTR32(x, n) (( x>>n  ) | (x<<(32-n)))
#define ROTL32(x, n) (( x<<n  ) | (x>>(32-n)))

// 1.1 使用普通C语言实现的AES128
const unsigned char S_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
const unsigned char inv_S_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
const unsigned char Rcon[11] =  {0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

static inline uint8_t GMul8(uint8_t u, uint8_t v) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (u & 0x01) p ^= v;
        int flag = v & 0x80;
        v <<= 1;
        if (flag) v ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        u >>= 1;
    }
    return p;
}
static inline void _transpose_4x4(uint8_t *state)
{
    uint32_t col1 = U8TO32_STRIDE4(state);
    uint32_t col2 = U8TO32_STRIDE4(state+1);
    uint32_t col3 = U8TO32_STRIDE4(state+2);
    uint32_t col4 = U8TO32_STRIDE4(state+3);
    *((uint32_t*)state) = col1;
    *((uint32_t*)(state+4)) = col2;
    *((uint32_t*)(state+8)) = col3;
    *((uint32_t*)(state+12)) = col4;
}

static inline void _xor_key(uint8_t* state, const uint8_t* key)
{
    for(int i=0;i<16;i++) state[i] ^= key[i];
}
static inline void _sub_bytes(uint8_t* state)
{
    for(int i=0;i<16;i++) state[i] = S_box[state[i]];
}
static inline void _shift_rows(uint8_t* state)
{
    uint32_t col0 = U8TO32_STRIDE4(state);
    uint32_t col1 = U8TO32_STRIDE4(state+1);
    uint32_t col2 = U8TO32_STRIDE4(state+2);
    uint32_t col3 = U8TO32_STRIDE4(state+3);
    *((uint32_t*)state) = col0;
    *((uint32_t*)(state+4)) = ROTR32(col1, 8);
    *((uint32_t*)(state+8)) = ROTR32(col2, 16);
    *((uint32_t*)(state+12)) = ROTR32(col3, 24);
}
static inline void _mix_columns(uint8_t* state)
{
    uint8_t tmp[16];
    memcpy(tmp, state, 16);

    for(int i=0;i<4;i++)
    {
        state[i*4] =    GMul8(0x02, tmp[i]) ^ GMul8(0x03, tmp[i+4]) ^ tmp[i+8]             ^ tmp[i+12];
        state[i*4+1]  = tmp[i]             ^ GMul8(0x02, tmp[i+4]) ^ GMul8(0x03, tmp[i+8]) ^ tmp[i+12];
        state[i*4+2]  = tmp[i]             ^ tmp[i+4]             ^ GMul8(0x02, tmp[i+8]) ^ GMul8(0x03, tmp[i+12]);
        state[i*4+3] =  GMul8(0x03, tmp[i]) ^ tmp[i+4]             ^ tmp[i+8]             ^ GMul8(0x02, tmp[i+12]);
    }
}

static inline void _inv_sub_bytes(uint8_t* state)
{
    for(int i=0;i<16;i++) state[i] = inv_S_box[state[i]];
}
static inline void _inv_shift_rows(uint8_t* state)
{
    *((uint32_t*)(state+4)) = ROTL32(*((uint32_t*)(state+4)), 8);
    *((uint32_t*)(state+8)) = ROTL32(*((uint32_t*)(state+8)), 16);
    *((uint32_t*)(state+12)) = ROTL32(*((uint32_t*)(state+12)), 24);
    _transpose_4x4(state);
}
static inline void _inv_mix_columns(uint8_t* state)
{
    uint8_t tmp[16];
    memcpy(tmp, state, 16);

    for(int i=0;i<4;i++)
    {
        int base = i*4;
        state[i] =    GMul8(0x0e, tmp[base]) ^ GMul8(0x0b, tmp[base+1]) ^ GMul8(0x0d, tmp[base+2]) ^ GMul8(0x09, tmp[base+3]);
        state[i+4]  = GMul8(0x09, tmp[base]) ^ GMul8(0x0e, tmp[base+1]) ^ GMul8(0x0b, tmp[base+2]) ^ GMul8(0x0d, tmp[base+3]);
        state[i+8]  = GMul8(0x0d, tmp[base]) ^ GMul8(0x09, tmp[base+1]) ^ GMul8(0x0e, tmp[base+2]) ^ GMul8(0x0b, tmp[base+3]);
        state[i+12] =  GMul8(0x0b, tmp[base]) ^ GMul8(0x0d, tmp[base+1]) ^ GMul8(0x09, tmp[base+2]) ^ GMul8(0x0e, tmp[base+3]);
    }
}

void AES128_Loadkey_naive(const uint8_t* key, uint8_t (*key_schedule)[16])
{
    memcpy(key_schedule[0], key, 16);

    uint8_t tmp_gw[4]; 
    for(int i=1;i<11;i++)
    {
        tmp_gw[0] = S_box[key_schedule[i-1][13]] ^ Rcon[i];
        tmp_gw[1] = S_box[key_schedule[i-1][14]];
        tmp_gw[2] = S_box[key_schedule[i-1][15]];
        tmp_gw[3] = S_box[key_schedule[i-1][12]];
        *((uint32_t*)key_schedule[i]) = *((uint32_t*)key_schedule[i-1]) ^ *((uint32_t*)tmp_gw);
        *((uint32_t*)(key_schedule[i]+4)) = *((uint32_t*)(key_schedule[i-1]+4)) ^ *((uint32_t*)(key_schedule[i]));
        *((uint32_t*)(key_schedule[i]+8)) = *((uint32_t*)(key_schedule[i-1]+8)) ^ *((uint32_t*)(key_schedule[i]+4));
        *((uint32_t*)(key_schedule[i]+12)) = *((uint32_t*)(key_schedule[i-1]+12)) ^ *((uint32_t*)(key_schedule[i]+8));
    }
}
void AES128_Encrypt_naive(const uint8_t* plaintext, const uint8_t (*key_schedule)[16], uint8_t* ciphertext)
{   
    memcpy(ciphertext, plaintext, 16);

    _xor_key(ciphertext, key_schedule[0]);
    for(int i=1;i<10;i++)
    {
        _sub_bytes(ciphertext);
        _shift_rows(ciphertext);
        _mix_columns(ciphertext);
        _xor_key(ciphertext, key_schedule[i]);
    }
    _sub_bytes(ciphertext);
    _shift_rows(ciphertext); _transpose_4x4(ciphertext); // 本代码实现_shift_rows、_mix_columns操作均会发生一次转置，故需这里需要加一次转置
    _xor_key(ciphertext, key_schedule[10]);
}
void AES128_Decrypt_naive(const uint8_t* ciphertext, const uint8_t (*key_schedule)[16], uint8_t* plaintext)
{
    memcpy(plaintext, ciphertext, 16);

    _xor_key(plaintext, key_schedule[10]); _transpose_4x4(plaintext); // 本代码实现_inv_shift_rows、_inv_mix_columns操作均会发生一次转置，故需这里需要加一次转置
    for(int i=9;i>0;i--)
    {
        _inv_sub_bytes(plaintext);
        _inv_shift_rows(plaintext);
        _xor_key(plaintext, key_schedule[i]);
        _inv_mix_columns(plaintext);
    }
    _inv_sub_bytes(plaintext);
    _inv_shift_rows(plaintext);
    _xor_key(plaintext, key_schedule[0]);
}


// 1.2 使用Intel AES-NI指令集intrinsic实现的AES128

static inline __m128i _keygen(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(_mm_slli_si128(key, 4), key);
    key = _mm_xor_si128(_mm_slli_si128(key, 4), key);
    key = _mm_xor_si128(_mm_slli_si128(key, 4), key);
    return _mm_xor_si128(key, keygened);
}

void AES128_Loadkey_x86(const uint8_t *key, __m128i* key_schedule)
{
    // 加密轮密钥
    key_schedule[0] = _mm_loadu_si128((const __m128i*) key);
	key_schedule[1]  = _keygen(key_schedule[0], _mm_aeskeygenassist_si128(key_schedule[0],0x01));
	key_schedule[2]  = _keygen(key_schedule[1], _mm_aeskeygenassist_si128(key_schedule[1],0x02));
	key_schedule[3]  = _keygen(key_schedule[2], _mm_aeskeygenassist_si128(key_schedule[2],0x04));
	key_schedule[4]  = _keygen(key_schedule[3], _mm_aeskeygenassist_si128(key_schedule[3],0x08));
	key_schedule[5]  = _keygen(key_schedule[4], _mm_aeskeygenassist_si128(key_schedule[4],0x10));
	key_schedule[6]  = _keygen(key_schedule[5], _mm_aeskeygenassist_si128(key_schedule[5],0x20));
	key_schedule[7]  = _keygen(key_schedule[6], _mm_aeskeygenassist_si128(key_schedule[6],0x40));
	key_schedule[8]  = _keygen(key_schedule[7], _mm_aeskeygenassist_si128(key_schedule[7],0x80));
	key_schedule[9]  = _keygen(key_schedule[8], _mm_aeskeygenassist_si128(key_schedule[8],0x1B));
	key_schedule[10] = _keygen(key_schedule[9], _mm_aeskeygenassist_si128(key_schedule[9],0x36));
    // 解密轮密钥
	key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
	key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
	key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
	key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
	key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
	key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
	key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
	key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
	key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

void AES128_Encrypt_x86(const uint8_t* plaintext, const __m128i* key_schedule, uint8_t* ciphertext)
{
    __m128i P = _mm_loadu_si128((__m128i*)plaintext);
    __m128i C = _mm_xor_si128(P, key_schedule[0]);
    C = _mm_aesenc_si128(C, key_schedule[1]);
    C = _mm_aesenc_si128(C, key_schedule[2]);
    C = _mm_aesenc_si128(C, key_schedule[3]);
    C = _mm_aesenc_si128(C, key_schedule[4]);
    C = _mm_aesenc_si128(C, key_schedule[5]);
    C = _mm_aesenc_si128(C, key_schedule[6]);
    C = _mm_aesenc_si128(C, key_schedule[7]);
    C = _mm_aesenc_si128(C, key_schedule[8]);
    C = _mm_aesenc_si128(C, key_schedule[9]);
    C = _mm_aesenclast_si128(C, key_schedule[10]);
    _mm_storeu_si128((__m128i*)ciphertext, C);
}

void AES128_Decrypt_x86(const uint8_t* ciphertext, const __m128i* key_schedule, uint8_t* plaintext)
{
    __m128i C = _mm_loadu_si128((__m128i*)ciphertext);
    __m128i P = _mm_xor_si128(C, key_schedule[10]);
    P = _mm_aesdec_si128(P, key_schedule[11]);
    P = _mm_aesdec_si128(P, key_schedule[12]);
    P = _mm_aesdec_si128(P, key_schedule[13]);
    P = _mm_aesdec_si128(P, key_schedule[14]);
    P = _mm_aesdec_si128(P, key_schedule[15]);
    P = _mm_aesdec_si128(P, key_schedule[16]);
    P = _mm_aesdec_si128(P, key_schedule[17]);
    P = _mm_aesdec_si128(P, key_schedule[18]);
    P = _mm_aesdec_si128(P, key_schedule[19]);
    P = _mm_aesdeclast_si128(P, key_schedule[0]);
    _mm_storeu_si128((__m128i*)plaintext, P);
}

// void AES_Encrypt_armv8(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext)
// {
// }