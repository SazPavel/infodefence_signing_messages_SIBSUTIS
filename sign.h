#ifndef sign_H
#define sign_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <locale.h>
#include <inttypes.h>
#include "randombytes.h"
#include "infodef.h"
#include "ciphers.h"
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#if HASH==256
#define LENGTH SHA256_DIGEST_LENGTH
SHA256_CTX hash;
#elif HASH==224
#define LENGTH SHA224_DIGEST_LENGTH
SHA256_CTX hash;
#elif HASH==512
#define LENGTH SHA512_DIGEST_LENGTH
SHA512_CTX hash;
#elif HASH==384
#define LENGTH SHA384_DIGEST_LENGTH
SHA512_CTX hash;
#else
#define LENGTH MD5_DIGEST_LENGTH
MD5_CTX hash;
#endif

void hash_init()
{
#if HASH==256
    SHA256_Init(&hash);
#elif HASH==224
    SHA224_Init(&hash);
#elif HASH==512
    SHA512_Init(&hash);
#elif HASH==384
    SHA384_Init(&hash);
#else
    MD5_Init(&hash);
#endif
}

void str2hash(char *str, int length, uint8_t *digest)
{
#if HASH==256
    SHA256_Update(&hash, str, length);
#elif HASH==224
    SHA224_Update(&hash, str, length);
#elif HASH==512
    SHA512_Update(&hash, str, length);
#elif HASH==384
    SHA384_Update(&hash, str, length);
#else
    MD5_Update(&hash, str, length);
#endif
}

void hash_finale(uint8_t *digest){
#if HASH==256
    SHA256_Final(digest, &hash);
#elif HASH==224
    SHA224_Final(digest, &hash);
#elif HASH==512
    SHA512_Final(digest, &hash);
#elif HASH==384
    SHA384_Final(digest, &hash);
#else
    MD5_Final(digest, &hash);
#endif
}

void make_sign_rsa(char *in, char *out, int_least64_t c, int_least64_t n);
void check_sign_rsa(char *in, char *out, int_least64_t d, int_least64_t n);
void make_sign_lgamal(char *in, char *out, int_least64_t p, int_least64_t x, int_least64_t g);
void check_sign_lgamal(char *in, char *out, int_least64_t p, int_least64_t y, int_least64_t g);
void inversion_generate(int_least64_t p, int_least64_t c, int_least64_t *d);
void gost_generate(int_least64_t p, int_least64_t q, int_least64_t *a, int_least64_t *x, int_least64_t *y);
void make_sign_gost(char *in, char *out, int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t x);
void check_sign_gost(char *in, char *out, int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t y);
void gost_save_public_key(int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t x);
void gost_save_private_key(int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t y);
void gost_load_public_key(int_least64_t *p, int_least64_t *q, int_least64_t *a, int_least64_t *x);
void gost_load_private_key(int_least64_t *p, int_least64_t *q, int_least64_t *a, int_least64_t *y);


#endif 
