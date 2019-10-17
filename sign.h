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

#define MD5 0
#define SHA256 1

void str2(char *str, int length, uint8_t *digest)
{
#if MD5
#define LENGTH MD5_DIGEST_LENGTH
    MD5_CTX hMD5;
    MD5_Init(&hMD5);
    MD5_Update(&hMD5, str, length);
    MD5_Final(digest, &hMD5);
#elif SHA256
#define LENGTH SHA256_DIGEST_LENGTH
    SHA256_CTX hSHA256;
    SHA256_Init(&hSHA256);
    SHA256_Update(&hSHA256, str, length);
    SHA256_Final(digest, &hSHA256);
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
