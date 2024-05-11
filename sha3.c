#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define IDX(i, j) ((j)*5 + (i))

static const uint64_t RND_CONST[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};
static const int RHOPI_ROTN[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};
static const int RHOPI_IDX[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};


static inline void _keccak_p_1600_24(uint64_t *state)
{
    for(int rnd=0; rnd<24; rnd++)
    {
        // theta()
        uint64_t tmp_plane[5], tmp_lane;
        for(int i=0; i<5; i++)
            tmp_plane[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20];
        for(int i=0; i<5; i++)
        {
            tmp_lane = tmp_plane[(i+4)%5] ^ ROTL64(tmp_plane[(i+1)%5], 1);
            for(int j=0; j<5; j++)
                state[IDX(i, j)] ^= tmp_lane;
        }

        // rho() & pi()
        int idx=1, n; uint64_t tmp_lane1=state[idx], tmp_lane2;
        for(int it=0; it<24; it++)
        {
            idx=RHOPI_IDX[it], n=RHOPI_ROTN[it];
            tmp_lane2 = state[idx];
            state[idx] = ROTL64(tmp_lane1, n);
            tmp_lane1 = tmp_lane2;
        }

        // chi()
        uint64_t tmp_state[25];
        memcpy(tmp_state, state, sizeof(uint64_t)*25);
        for(int j=0; j<5; j++)
        for(int i=0; i<5; i++)
            state[IDX(i, j)] ^= (~tmp_state[IDX((i + 1) % 5, j)]) & tmp_state[IDX((i + 2) % 5, j)];

        // iota()
        state[0] ^= RND_CONST[rnd];
    }

}

static inline void _SHA3_naive(size_t msg_size, const uint8_t* msg, uint8_t* hash, int hash_bits)
{
    // keccak params
    size_t c_size = 2 * (hash_bits>>3), 
           r_size = 200 - c_size, 
           n_iter = (msg_size / r_size) + 1,
           msg_ptr = 0;
    uint64_t state[25] = {0};

    // sponge iter
    for(size_t it=0; it<(n_iter-1); it++)
    {
        for(size_t i=0; i<(r_size>>3); i++) state[i] ^= ((uint64_t*)(msg+msg_ptr))[i];
        _keccak_p_1600_24(state);
        msg_ptr += r_size;
    }

    // sponge last iter
    uint8_t* state_byte_ptr = ((uint8_t*)state);
    while(msg_ptr<msg_size)
        *(state_byte_ptr++) ^= msg[msg_ptr++];
    // concat '01' & pad10*1
    *state_byte_ptr ^= 0x06;
    ((uint8_t*)state)[r_size-1] ^= 0x80;
    _keccak_p_1600_24(state);    

    // trunc hash
    for (int i=0; i<(hash_bits>>3); i++)
        hash[i] = ((uint8_t*)state)[i];
}

void SHA3_256_naive(size_t msg_size, const uint8_t* msg, uint8_t* hash)
{
    _SHA3_naive(msg_size, msg, hash, 256);
}

void SHA3_512_naive(size_t msg_size, const uint8_t* msg, uint8_t* hash)
{
    _SHA3_naive(msg_size, msg, hash, 512);
}