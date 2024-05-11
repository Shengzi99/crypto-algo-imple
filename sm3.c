#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LOAD_WORD(byte_ptr) ( (((uint32_t)((byte_ptr)[0]))<<24) | (((uint32_t)((byte_ptr)[1]))<<16) | (((uint32_t)((byte_ptr)[2]))<<8) | (((uint32_t)((byte_ptr)[3]))) )
#define SWITCH_END32(U32) (((U32)>>24) | (((U32)>>8)&0x0000ff00) | (((U32)<<8)&0x00ff0000) | ((U32)<<24))
#define SWITCH_END64(U64) (((U64)>>56) | (((U64)>>40)&0x000000000000ff00) | (((U64)>>24)&0x0000000000ff0000) | (((U64)>>8)&0x00000000ff000000) | (((U64)<<8)&0x000000ff00000000) | (((U64)<<24)&0x0000ff0000000000) | (((U64)<<40)&0x00ff000000000000) | ((U64)<<56))
#define ROTR32(x, n) (( (x)>>(n)  ) | ((x)<<(32-(n))))
#define ROTL32(x, n) (( (x)<<(n)  ) | ((x)>>(32-(n))))
#define FF1GG1(X,Y,Z) ((X)^(Y)^(Z))
#define FF2(X,Y,Z) ( ((X)&(Y)) | ((X)&(Z)) | ((Y)&(Z)) )
#define GG2(X,Y,Z) ( ((X)&(Y)) | ((~X)&(Z)) )
#define P0(X) ((X) ^ ROTL32(X, 9) ^ ROTL32(X, 17))
#define P1(X) ((X) ^ ROTL32(X, 15) ^ ROTL32(X, 23))
const uint32_t T1=0x79cc4519UL;
const uint32_t T2=0x7A879D8AUL;


static inline void _sm3_blk_exp(const uint8_t *B, uint32_t *W)
{
    for(size_t j=0; j<16; j++)
        W[j] = LOAD_WORD( (B+(j*4)) );
    for(size_t j=16; j<68; j++)
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15)) ^ ROTL32(W[j-13], 7) ^ W[j-6];
}
static inline void _sm3_comp_func(uint32_t *V, const uint32_t *W)
{
    uint32_t A=V[0], B=V[1], C=V[2], D=V[3], E=V[4], F=V[5], G=V[6], H=V[7];
    uint32_t SS1, SS2, TT1, TT2;
    for(size_t j=0; j<16; j++)
    {
        SS1 = ROTL32( ROTL32(A, 12) + E + ROTL32(T1, j), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF1GG1(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
        TT2 = FF1GG1(E, F, G) + H + SS1 + W[j];
        D = C; 
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }
    for(size_t j=16; j<64; j++)
    {
        SS1 = ROTL32( (ROTL32(A, 12) + E + ROTL32(T2, j)), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF2(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
        TT2 = GG2(E, F, G) + H + SS1 + W[j];
        D = C; 
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }
    V[0]^=A, V[1]^=B, V[2]^=C, V[3]^=D, V[4]^=E, V[5]^=F, V[6]^=G, V[7]^=H;
}

void SM3_256_naive(uint64_t msg_size, const uint8_t* msg, uint8_t* hash)
{
    uint64_t n_iter = msg_size / 64, msg_idx=0;
    uint32_t W[68], V[8]={0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E};
    uint8_t last_blk[64] = {0};

    // 前n_iter个迭代
    for(uint64_t i=0; i<n_iter; i++)
    {
        _sm3_blk_exp(msg+msg_idx, W);
        _sm3_comp_func(V, W);
        msg_idx += 64;
    }
    // 最后一个迭代，需要填充
    size_t idx=0;
    while(msg_idx < msg_size) last_blk[idx++] = msg[msg_idx++];
    last_blk[idx] = 0x80;
    *((uint64_t*)(last_blk+56)) = SWITCH_END64(msg_size*8);
    _sm3_blk_exp(last_blk, W);
    _sm3_comp_func(V, W);
    
    // 导出hash
    for(int i=0; i<8; i++)
        ((uint32_t*)hash)[i] = SWITCH_END32(V[i]);
}