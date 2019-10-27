#include "sign.h"

void inversion_generate(int_least64_t p, int_least64_t c, int_least64_t *d)
{
    int_least64_t am[3], bm[3];
    do
    {
        am[0] = p; am[1] = 1; am[2] = 0;
        bm[0] = c; bm[1] = 0; bm[2] = 1;
        gcd_v(am, bm);
    }while(am[0] != 1);
    if(am[2] < 0)
        am[2] += p;
    *d = am[2];
}

void gost_generate_prime(int_least64_t *p, int_least64_t *q, int_least64_t *b)
{
    int flag = 1;
    while(flag)
    {
        flag = 1;
        while(1)
        {
            randombytes(p, sizeof(*p));
            *p = fabs(*p % (int_least64_t)(((int_least64_t)2 << 30) - 1)) + ((int_least64_t)2 << 30);
            if(prime_test(*p))
                break;
        }
        while(1)
        {
            randombytes(q, sizeof(*q));
            *q = fabs(*q % (int_least64_t)(((int_least64_t)2 << 14) - 1)) + ((int_least64_t)2 << 14);
            if(prime_test(*q))
                break;
        }
        while(flag && *q < (2 << 15))
        {
            *q += 2;
            if(!prime_test(*q))
                continue;
            for(*b = 4; *b < *q; *b += 2)
            {
                if(*q * *b + 1  == *p)
                {
                    flag = 0;
                    break;
                }
            }
        }
    }
}



void gost_generate(int_least64_t p, int_least64_t q, int_least64_t b, int_least64_t *a, int_least64_t *x, int_least64_t *y)
{
    int_least64_t g;
    for(g = 2; g < p - 1; g += 1)
    {
        *a = modpow(g, b, p);
        if(*a != 1) 
            break;
    }
    randombytes(x, sizeof(*x));
    *x = fabs(*x % (int_least64_t)(q-2)) + 1;
    *y = modpow(*a, *x, p);
    
}

void make_sign_gost(char *in, char *out, int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t x)
{
    uint8_t digest[LENGTH];
    char buffer[512];
    int_least64_t k, r, s;
    int cycle = 1;
    memset (buffer, 0, sizeof(buffer)); 
    int i, flag = 1;
    FILE *fin = file_open(in, "r");
    FILE *fout = file_open(out, "w");
    hash_init();
    while(flag)
    {
        if(fread(buffer, sizeof(char), 512, fin) != 512) 
            if(feof(fin)) flag = 0;
        str2hash(buffer, sizeof(buffer), digest);
    }
    hash_finale(digest);
    for (i = 0; i < LENGTH; i++)
    {
        while(cycle)
        {
            randombytes(&k, sizeof(k));
            k = fabs(k % (int_least64_t)(q-3)) + 2;
            r = modpow(a, k, p) % q;
            if(r == 0)
                continue;
            s = ((k * digest[i]) % q + (x * r) % q) % q;
            if(s != 0)
                cycle = 0;  
        }
        cycle = 1;
        fprintf(fout, "%"PRId64" %"PRId64"\n", r, s);
    }
    fclose(fin);
    fclose(fout);
}

void check_sign_gost(char *in, char *out, int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t y)
{
    uint8_t digest[LENGTH];
    int_least64_t v, u1, u2, r, s, inh;
    char buffer[512];
    memset (buffer, 0, sizeof(buffer)); 
    int i = 0, flag = 1;
    FILE *fin = file_open(in, "r");
    FILE *fout = file_open(out, "r");
    hash_init();
    while(flag)
    {
        if(fread(buffer, sizeof(char), 512, fin) != 512) 
            if(feof(fin)) flag = 0;
        str2hash(buffer, sizeof(buffer), digest);
    }
    hash_finale(digest);
    while(fscanf(fout, "%"PRId64" %"PRId64, &r, &s) != EOF)
    {
        if(r > q || s > q || r < 0 || s < 0)
            printf("ERROR\n");
        inversion_generate(q, digest[i], &inh);
        u1 = (s * inh) % q;
        u2 = (-r * inh) % q;
        if(u2 < 0)
            u2 += q;
        v = ((modpow(a, u1, p) * modpow(y, u2, p)) % p)% q;
        if(v != r)
        {
            printf("ERROR\n");
        }
        i++;
    }
    for(i = 0; i < LENGTH; i++)
        printf("%02x", digest[i]);
    printf("\n");
    fclose(fin);
    fclose(fout);
}

void gost_save_public_key(int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t x)
{
    FILE *fout = file_open("tmp/gost_public_key", "w");
    fprintf(fout, "%"PRId64" %"PRId64" %"PRId64" %"PRId64"\n", p, q, a, x);
    fclose(fout);
}

void gost_save_private_key(int_least64_t p, int_least64_t q, int_least64_t a, int_least64_t y)
{
    FILE *fout = file_open("tmp/gost_private_key", "w");
    fprintf(fout, "%"PRId64" %"PRId64" %"PRId64" %"PRId64"\n", p, q, a, y);
    fclose(fout);
}

void gost_load_public_key(int_least64_t *p, int_least64_t *q, int_least64_t *a, int_least64_t *x)
{
    FILE *fout = file_open("tmp/gost_public_key", "r");
    fscanf(fout, "%"PRId64" %"PRId64" %"PRId64" %"PRId64, p, q, a, x);
    fclose(fout);
}

void gost_load_private_key(int_least64_t *p, int_least64_t *q, int_least64_t *a, int_least64_t *y)
{
    FILE *fout = file_open("tmp/gost_private_key", "r");
    fscanf(fout, "%"PRId64" %"PRId64" %"PRId64" %"PRId64, p, q, a, y);
    fclose(fout);
}

int main(int argc, char *argv[])
{
    setlocale (LC_ALL, "Rus");
    int temp;
    int_least64_t p, q, a, x, y, b;
    if(argc < 3)
    {
        printf("example: ./gost filename command(1 - generate keys, 2 - encrypt, 3 - decrypt, 4 - all)\n");
        exit(0);
    }
    sscanf(argv[2], "%d", &temp);
    switch(temp)
    {
         case 1:
            gost_generate_prime(&p, &q, &b);
            gost_generate(p, q, b, &a, &x, &y);
            gost_save_private_key(p, q, a, x);
            gost_save_public_key(p, q, a, y);
            break;  
        case 2:
            gost_load_private_key(&p, &q, &a, &x);
            make_sign_gost(argv[1], "tmp/sign_gost", p, q, a, x);
            break;
        case 3:
            gost_load_public_key(&p, &q, &a, &y);
            check_sign_gost(argv[1], "tmp/sign_gost", p, q, a, y);
            break;
        case 4:
            gost_generate_prime(&p, &q, &b);
            gost_generate(p, q, b, &a, &x, &y);
            make_sign_gost(argv[1], "tmp/sign_gost", p, q, a, x);
            check_sign_gost(argv[1], "tmp/sign_gost", p, q, a, y);
            break;
    }    
    exit(0);
}
