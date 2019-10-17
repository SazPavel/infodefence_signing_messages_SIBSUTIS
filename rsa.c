#include "sign.h"

void make_sign_rsa(char *in, char *out, int_least64_t c, int_least64_t n)
{
    uint8_t digest[LENGTH];
    char buffer[512];
    memset (buffer, 0, sizeof(buffer)); 
    int i, flag = 1;
    FILE *fin = file_open(in, "r");
    FILE *fout = file_open(out, "w");
    while(flag)
    {
        if(fread(buffer, sizeof(char), 512, fin) != 512) 
            if(feof(fin)) flag = 0;
        str2(buffer, sizeof(buffer), digest);
    }
    for (i = 0; i < LENGTH; i++)
    {
        
        fprintf(fout, "%"PRId64" ", modpow(digest[i], c, n));
    }
    fclose(fin);
    fclose(fout);
}

void check_sign_rsa(char *in, char *out, int_least64_t d, int_least64_t n)
{
    uint8_t digest[LENGTH], test_sign[LENGTH];
    int_least64_t tmp;
    char buffer[512];
    memset (buffer, 0, sizeof(buffer)); 
    int i = 0, flag = 1;
    FILE *fin = file_open(in, "r");
    FILE *fout = file_open(out, "r");
    while(flag)
    {
        if(fread(buffer, sizeof(char), 512, fin) != 512) 
            if(feof(fin)) flag = 0;
        str2(buffer, sizeof(buffer), digest);
    }
    while(fscanf(fout, "%"PRId64, &tmp) != EOF)
    {
        test_sign[i] = (modpow(tmp, d, n));
        i++;
    }
    for(i = 0; i < LENGTH; i++)
    {
        if(test_sign[i] != digest[i])
            printf("ERROR\n");
    }
    for (i = 0; i < LENGTH; i++)
        printf("%02x", digest[i]);
    printf("\n");
    fclose(fin);
    fclose(fout);
}

int main(int argc, char *argv[])
{
    setlocale (LC_ALL, "Rus");
    int temp;
    int_least64_t n, c, d;
    if(argc < 3)
    {
        printf("example: ./rsa filename command(1 - generate keys, 2 - encrypt, 3 - decrypt, 4 - all)\n");
        exit(0);
    }
    sscanf(argv[2], "%d", &temp);
    switch(temp)
    {
        case 1:
            rsa_generate(&n, &c, &d);
            rsa_save_public_key(n, d);
            rsa_save_private_key(n, c);
            break;  
        case 2:
            rsa_load_private_key(&n, &c);
            make_sign_rsa(argv[1], "tmp/sign_rsa", c, n);
            break;
        case 3:
            rsa_load_public_key(&n, &d);
            check_sign_rsa(argv[1], "tmp/sign_rsa", d, n);
            break;
        case 4:
            rsa_generate(&n, &c, &d);
            make_sign_rsa(argv[1], "tmp/sign_rsa", c, n);
            check_sign_rsa(argv[1], "tmp/sign_rsa", d, n);
            break;        
    }    
    exit(0);
}
