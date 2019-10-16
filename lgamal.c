#include "ciphers.h"
#include <string.h>
#include <math.h>
#include <openssl/md5.h>

void lgamal_sign_generate(int_least64_t p, int_least64_t *c, int_least64_t *d)
{
    int_least64_t am[3], bm[3];
    do
    {
        randombytes(c, sizeof(*c));
        *c = fabs(*c % (int_least64_t)(p-2)) + 2;
        am[0] = p; am[1] = 1; am[2] = 0;
        bm[0] = *c; bm[1] = 0; bm[2] = 1;
        gcd_v(am, bm);
    }while(am[0] != 1);
    if(am[2] < 0)
        am[2] += (p);
    *d = am[2];
}

void str2MD5(char *str, int length, uint8_t *digest)
{
    MD5_CTX hMD5;
    MD5_Init(&hMD5);
    MD5_Update(&hMD5, str, length);
    MD5_Final(digest, &hMD5);
}

void make_sign_lgamal(char *in, char *out, int_least64_t p, int_least64_t x, int_least64_t g)
{
    uint8_t digest[MD5_DIGEST_LENGTH];
    int_least64_t k, ink, r, u, s;
    char buffer[512];
    memset (buffer, 0, sizeof(buffer)); 
    int i, flag = 1;
    
    lgamal_sign_generate(p-1, &k, &ink);
    r = modpow(g, k ,p);
    FILE *fin = file_open(in, "r");
    FILE *fout = file_open(out, "w");
    while(flag)
    {
        if(fread(buffer, sizeof(char), 512, fin) != 512) 
            if(feof(fin)) flag = 0;
        str2MD5(buffer, sizeof(buffer), digest);
    }
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        u = (digest[i] - x * r) % (p-1);
        if(u < 0)
            u += (p-1);
        s = (ink * u) % (p-1);
        fprintf(fout, "%"PRId64" %"PRId64"\n", r, s);
    }
    fclose(fin);
    fclose(fout);
}

void check_sign_lgamal(char *in, char *out, int_least64_t p, int_least64_t y, int_least64_t g)
{
    uint8_t digest[MD5_DIGEST_LENGTH];
    int_least64_t r, s, test_sign[MD5_DIGEST_LENGTH];
    char buffer[512];
    memset (buffer, 0, sizeof(buffer)); 
    int i = 0, flag = 1;
    FILE *fin = file_open(in, "r");
    FILE *fout = file_open(out, "r");
    while(flag)
    {
        if(fread(buffer, sizeof(char), 512, fin) != 512) 
            if(feof(fin)) flag = 0;
        str2MD5(buffer, sizeof(buffer), digest);
    }
    while(fscanf(fout, "%"PRId64" %"PRId64, &r, &s) != EOF)
    {
        test_sign[i] = (modpow(y, r, p) * modpow(r, s, p)) % p;
        i++;
    }
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        if(test_sign[i] != modpow(g, digest[i], p))
        {
            printf("ERROR\n");\
            
        }
    }
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
        printf("%02x", digest[i]);
    printf("\n");
    fclose(fin);
    fclose(fout);
}

int main(int argc, char *argv[])
{
    setlocale (LC_ALL, "Rus");
    int temp;
    int_least64_t p, x, y, g;
    if(argc < 3)
    {
        printf("example: ./lgamal filename command(1 - generate keys, 2 - encrypt, 3 - decrypt, 4 - all)\n");
        exit(0);
    }
    sscanf(argv[2], "%d", &temp);
    switch(temp)
    {
        case 1:
            prime_safe_generate(&p, &g, 1e9, 256);
            lgamal_generate_xy(p, g, &x, &y);
            lgamal_save_public_key(p, y, g);
            lgamal_save_private_key(p, x);
            break;  
        case 2:
            lgamal_load_private_key(&p, &x);
            lgamal_load_public_key(&p, &y, &g);
            make_sign_lgamal(argv[1], "tmp/lgamal_sign",p, x, g);
            break;
        case 3:
            lgamal_load_public_key(&p, &y, &g);
            check_sign_lgamal(argv[1], "tmp/lgamal_sign", p, y, g);
            break;
        case 4:
            prime_safe_generate(&p, &g, 1e9, 256);
            lgamal_generate_xy(p, g, &x, &y);
            make_sign_lgamal(argv[1], "tmp/lgamal_sign", p, x, g);
            check_sign_lgamal(argv[1], "tmp/lgamal_sign", p, y, g);
            break;        
    }
    exit(0);
}
