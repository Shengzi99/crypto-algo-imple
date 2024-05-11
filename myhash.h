#include <stdint.h>
#include <stddef.h>


// SHA3 naive
void SHA3_256_naive(size_t msg_size, const uint8_t* msg, uint8_t* hash);
void SHA3_512_naive(size_t msg_size, const uint8_t* msg, uint8_t* hash);

// SM3 256
void SM3_256_naive(size_t msg_size, const uint8_t* msg, uint8_t* hash);